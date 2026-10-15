//! State digests across the lab: every running member's own digest, asked through its own
//! API (`GET /cluster/digests?revision=`). Equal digests at the same revision mean the
//! members hold the same state, so no committed write was lost on any of them.

use serde_json::Value;

use super::lab::{ClusterLab, SETTLE_LIMIT};

/// The members agree on their state at one revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agreement {
    /// The revision every member computed its digest at.
    pub revision: u64,
    /// The SHA-256 every member reported.
    pub sha256: String,
    /// The members that took part (every running controller).
    pub members: Vec<u64>,
}

impl ClusterLab {
    /// The digest report of one controller, at `revision` or at the newest revision when
    /// absent; `None` when it does not answer 200.
    pub fn digest_report(&self, id: u64, revision: Option<u64>) -> Option<Value> {
        let path = revision.map_or_else(
            || "/cluster/digests".to_owned(),
            |revision| format!("/cluster/digests?revision={revision}"),
        );
        let reply = self.get(id, &path)?;
        (reply.status == 200).then(|| reply.json())
    }

    /// Waits until every running controller reports, through its own API, the same digest
    /// for itself at one revision of at least `at_least`. Fails at once when two members
    /// computed different digests at the same revision.
    #[track_caller]
    pub fn digests_agree(&self, at_least: u64) -> Agreement {
        self.wait_until(
            &format!("equal digests at revision {at_least} or later"),
            SETTLE_LIMIT,
            || {
                let (leader, _) = self.current_leader()?;
                let revision = self.digest_report(leader, None)?["revision"].as_u64()?;
                if revision < at_least {
                    return None;
                }
                let mut agreed: Option<(u64, String)> = None;
                let members = self.ids();
                for id in &members {
                    let report = self.digest_report(*id, Some(revision))?;
                    let own = report["members"]
                        .as_array()?
                        .iter()
                        .find(|member| member["node"].as_u64() == Some(*id))?
                        .clone();
                    if own["revision"].as_u64() != Some(revision) {
                        return None;
                    }
                    let digest = own["sha256"].as_str()?.to_owned();
                    match &agreed {
                        None => agreed = Some((*id, digest)),
                        Some((first, sha)) => assert_eq!(
                            *sha,
                            digest,
                            "controllers {first} and {id} hold different state at revision \
                             {revision}\n{report}\n{}",
                            self.diagnostics()
                        ),
                    }
                }
                let (_, sha256) = agreed?;
                Some(Agreement {
                    revision,
                    sha256,
                    members,
                })
            },
        )
    }
}
