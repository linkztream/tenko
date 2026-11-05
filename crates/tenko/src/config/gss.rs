//! `[dns.gss]`: the TKEY contexts of GSS-TSIG on this node (identity plan section 3.3,
//! WP13.0; `docs/dns.md` section 13). The keys are read and checked at start; nothing uses
//! them until the TKEY handler arrives (WP13.2). Keys that are not set follow the security
//! profile in force when the role starts.

use serde::{Deserialize, Serialize};
use tenko_auth::settings::Profile;

use super::ConfigError;

/// `[dns.gss]`: the bounds of the context table and the clock skew the acceptor allows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsGssSection {
    /// Seconds an established context lives at most, 60 to 86,400 (default 3,600, BIND's
    /// fallback); the ticket's end time cuts it shorter. The client negotiates again.
    pub context_max_secs: u64,
    /// Established contexts per node at most, 100 to 1,000,000; the oldest idle one leaves
    /// first when the table is full. Not set: 10,000, 2,000 under the Home profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contexts_max: Option<usize>,
    /// Negotiations in flight per node at most, 10 to 100,000; one not completed within
    /// 30 s is dropped. Not set: 1,000, 200 under the Home profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negotiating_max: Option<usize>,
    /// Negotiations in flight per client address at most, 1 to 1,024 (default 32).
    pub per_client_max: usize,
    /// Seconds of clock skew the acceptor allows between a client's authenticator and the
    /// node, 1 to 900 (default 300, RFC 4120's five minutes).
    pub skew_secs: u64,
}

impl Default for DnsGssSection {
    fn default() -> Self {
        Self {
            context_max_secs: 3_600,
            contexts_max: None,
            negotiating_max: None,
            per_client_max: 32,
            skew_secs: 300,
        }
    }
}

impl DnsGssSection {
    /// The established contexts the node holds at most: the key, or the profile's default
    /// (2,000 under Home, 10,000 under the others).
    pub fn contexts_max_for(&self, profile: Profile) -> usize {
        self.contexts_max.unwrap_or(match profile {
            Profile::Home => 2_000,
            _ => 10_000,
        })
    }

    /// The negotiations in flight the node holds at most: the key, or the profile's
    /// default (200 under Home, 1,000 under the others).
    pub fn negotiating_max_for(&self, profile: Profile) -> usize {
        self.negotiating_max.unwrap_or(match profile {
            Profile::Home => 200,
            _ => 1_000,
        })
    }

    /// The bounds of every key, independent of the profile.
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        fn within<T: PartialOrd + Copy>(
            value: T,
            low: T,
            high: T,
            key: &str,
            range: &str,
        ) -> Result<(), ConfigError> {
            if (low..=high).contains(&value) {
                Ok(())
            } else {
                Err(ConfigError::invalid(format!(
                    "dns.gss.{key} must be between {range}"
                )))
            }
        }
        within(
            self.context_max_secs,
            60,
            86_400,
            "context_max_secs",
            "60 and 86400",
        )?;
        if let Some(contexts) = self.contexts_max {
            within(contexts, 100, 1_000_000, "contexts_max", "100 and 1000000")?;
        }
        if let Some(negotiating) = self.negotiating_max {
            within(negotiating, 10, 100_000, "negotiating_max", "10 and 100000")?;
        }
        within(
            self.per_client_max,
            1,
            1_024,
            "per_client_max",
            "1 and 1024",
        )?;
        within(self.skew_secs, 1, 900, "skew_secs", "1 and 900")?;
        if let (Some(negotiating), Some(contexts)) = (self.negotiating_max, self.contexts_max)
            && negotiating > contexts
        {
            return Err(ConfigError::invalid(
                "dns.gss.negotiating_max is at most dns.gss.contexts_max",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Resolved, Sources, load};

    fn resolve(text: &str) -> Result<Resolved, ConfigError> {
        let data = std::env::temp_dir().join("tenko-config-dns-gss");
        let text = format!("data_dir = {:?}\n{text}", data.display().to_string());
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("tenko.toml");
        std::fs::write(&path, text).expect("write configuration");
        load(
            &Sources {
                file: Some(path),
                ..Sources::default()
            },
            Vec::new(),
        )
        .and_then(|loaded| loaded.config.resolve())
    }

    fn gss(text: &str) -> DnsGssSection {
        resolve(text).expect("valid").config.dns.gss
    }

    fn refused(text: &str, needle: &str) {
        let error = resolve(text).expect_err(text);
        assert_eq!(error.code, "config.invalid", "{text}");
        assert!(error.message.contains(needle), "{text}: {error}");
    }

    #[test]
    fn the_defaults_follow_section_3_3_and_the_profile() {
        let section = gss("");
        assert_eq!(section, DnsGssSection::default());
        assert_eq!(
            (
                section.context_max_secs,
                section.per_client_max,
                section.skew_secs
            ),
            (3_600, 32, 300)
        );
        assert_eq!(section.contexts_max, None);
        assert_eq!(section.negotiating_max, None);
        for (profile, contexts, negotiating) in [
            (Profile::Home, 2_000, 200),
            (Profile::Standard, 10_000, 1_000),
            (Profile::Hardened, 10_000, 1_000),
            (Profile::Lab, 10_000, 1_000),
        ] {
            assert_eq!(section.contexts_max_for(profile), contexts, "{profile:?}");
            assert_eq!(
                section.negotiating_max_for(profile),
                negotiating,
                "{profile:?}"
            );
        }
    }

    #[test]
    fn a_key_that_is_set_wins_and_is_bounded() {
        let section = gss(
            "[dns.gss]\ncontext_max_secs = 600\ncontexts_max = 500\nnegotiating_max = 50\n\
             per_client_max = 8\nskew_secs = 60\n[profile]\nname = \"home\"\n",
        );
        assert_eq!(section.context_max_secs, 600);
        assert_eq!(section.contexts_max_for(Profile::Home), 500);
        assert_eq!(section.negotiating_max_for(Profile::Home), 50);
        assert_eq!((section.per_client_max, section.skew_secs), (8, 60));
        refused(
            "[dns.gss]\ncontext_max_secs = 59\n",
            "dns.gss.context_max_secs",
        );
        refused(
            "[dns.gss]\ncontext_max_secs = 86401\n",
            "dns.gss.context_max_secs",
        );
        refused("[dns.gss]\ncontexts_max = 99\n", "dns.gss.contexts_max");
        refused(
            "[dns.gss]\nnegotiating_max = 9\n",
            "dns.gss.negotiating_max",
        );
        refused("[dns.gss]\nper_client_max = 0\n", "dns.gss.per_client_max");
        refused(
            "[dns.gss]\nper_client_max = 1025\n",
            "dns.gss.per_client_max",
        );
        refused("[dns.gss]\nskew_secs = 0\n", "dns.gss.skew_secs");
        refused("[dns.gss]\nskew_secs = 901\n", "dns.gss.skew_secs");
        refused(
            "[dns.gss]\ncontexts_max = 200\nnegotiating_max = 300\n",
            "at most dns.gss.contexts_max",
        );
        let unknown = resolve("[dns.gss]\nticket_secs = 1\n").expect_err("an unknown key");
        assert_eq!(unknown.code, "config.parse");
        assert!(unknown.message.contains("ticket_secs"), "{unknown}");
    }
}
