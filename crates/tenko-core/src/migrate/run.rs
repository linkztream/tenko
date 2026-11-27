//! The record of a takeover run (ADR 0038, `docs/plans/windows-takeover-plan.md` section
//! 2.16.2): the sittings of the takeover script that act for one run of a domain, each a
//! person's approval collected as a delegated session, and the mirrors the run created.
//!
//! The run's id is the delegation of every sitting's session, so everything a sitting creates
//! names its run in its stamp. A row is an open run: the first collect of a domain creates it
//! with the approval's plan, a later collect with an equal plan joins it, and only a person's
//! close removes it. `tenko_auth` writes the three tables of [`super::tables`] together.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    Timestamp,
    dns::DnsName,
    id::{ApprovalId, DelegationId, MirrorId, SessionId, UserId},
    net::Fqdn,
    serde_util::HexBytes,
};

/// The sittings a run keeps: the newest, the oldest dropped (the audit holds every collect).
pub const MAX_SITTINGS: usize = 64;

/// An open run (`migrate.runs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RunRecord {
    /// The run's id: the delegation of every sitting's session.
    #[schema(value_type = String, format = Uuid)]
    pub id: DelegationId,
    /// The plan's domain.
    #[schema(value_type = String)]
    pub domain: DnsName,
    /// When its first sitting was collected, on the collecting controller's clock.
    #[schema(value_type = String, format = DateTime)]
    pub created_at: Timestamp,
    /// Its sittings, oldest first, at most [`MAX_SITTINGS`].
    pub sittings: Vec<Sitting>,
    /// The mirrors its sessions created: at most one per DHCP server of the plan.
    #[serde(default)]
    pub mirrors: Vec<RunMirror>,
    /// The window a person started: from then on the run creates no mirror and no zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<RunWindow>,
}

/// The window of a run (plan section 2.16.5): the configuration of each DHCP server the
/// person bound when they started it. Only a person replaces it; the run's close ends it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RunWindow {
    /// The name of the person who started it.
    pub started_by: String,
    /// When, on the binding controller's clock.
    #[schema(value_type = String, format = DateTime)]
    pub started_at: Timestamp,
    /// One entry per DHCP server of the plan: the run's mirror of it.
    pub mirrors: Vec<WindowMirror>,
}

/// A mirror the window bound, with the configuration hash the person was shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct WindowMirror {
    /// The run's mirror.
    #[schema(value_type = String, format = Uuid)]
    pub mirror: MirrorId,
    /// Its stored configuration's hash (`last_hash`), lowercase hexadecimal.
    pub hash: HexBytes,
}

/// A mirror a person binds (`POST /migrate/runs/{id}/window`): a [`WindowMirror`] that refuses
/// an unknown field, which the stored one ignores.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct WindowEntry {
    /// The run's mirror.
    pub mirror: MirrorId,
    /// The configuration hash the person was shown (`last_hash`), lowercase hexadecimal.
    pub hash: HexBytes,
}

/// One sitting of a run: an approval and the delegated session collected for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Sitting {
    /// The approval.
    #[schema(value_type = String, format = Uuid)]
    pub approval: ApprovalId,
    /// The person who approved it.
    #[schema(value_type = String, format = Uuid)]
    pub approved_by: UserId,
    /// The delegated session.
    #[schema(value_type = String, format = Uuid)]
    pub session: SessionId,
    /// The approval's source address, the only one the session is accepted from.
    #[schema(value_type = String)]
    pub source: IpAddr,
    /// When it was approved.
    #[schema(value_type = String, format = DateTime)]
    pub approved_at: Timestamp,
    /// When the script collected it.
    #[schema(value_type = String, format = DateTime)]
    pub collected_at: Timestamp,
}

/// A mirror of a run, with the plan's DHCP server it is named for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RunMirror {
    /// The DHCP server.
    #[schema(value_type = String)]
    pub server: Fqdn,
    /// The mirror.
    #[schema(value_type = String, format = Uuid)]
    pub mirror: MirrorId,
}

/// The open run an approval would join, as the person reads it before approving.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RunSummary {
    /// The run's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: DelegationId,
    /// When its first sitting was collected.
    #[schema(value_type = String, format = DateTime)]
    pub created_at: Timestamp,
    /// How many sittings it keeps.
    pub sittings: usize,
    /// The source address of its newest sitting.
    #[schema(value_type = Option<String>)]
    pub last_source: Option<IpAddr>,
}

impl RunRecord {
    /// Adds `sitting` as the newest, dropping the oldest past [`MAX_SITTINGS`].
    pub fn add_sitting(&mut self, sitting: Sitting) {
        self.sittings.push(sitting);
        if self.sittings.len() > MAX_SITTINGS {
            self.sittings.remove(0);
        }
    }

    /// What the person who approves a joining sitting reads of it.
    pub fn summary(&self) -> RunSummary {
        RunSummary {
            id: self.id,
            created_at: self.created_at,
            sittings: self.sittings.len(),
            last_source: self.sittings.last().map(|sitting| sitting.source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_keeps_its_newest_sittings() {
        let at: Timestamp = "2026-11-26T10:00:00Z".parse().expect("a time");
        let sitting = |last: u8| Sitting {
            approval: ApprovalId::generate(),
            approved_by: UserId::generate(),
            session: SessionId::generate(),
            source: IpAddr::from([192, 0, 2, last]),
            approved_at: at,
            collected_at: at,
        };
        let mut run = RunRecord {
            id: DelegationId::generate(),
            domain: "corp.example.test".parse().expect("a name"),
            created_at: at,
            sittings: Vec::new(),
            mirrors: Vec::new(),
            window: None,
        };
        let first = sitting(0);
        run.add_sitting(first.clone());
        for last in 1..=64 {
            run.add_sitting(sitting(last));
        }
        assert_eq!(run.sittings.len(), MAX_SITTINGS);
        assert!(!run.sittings.contains(&first), "the oldest is gone");
        let summary = run.summary();
        assert_eq!(summary.sittings, 64);
        assert_eq!(summary.last_source, Some(IpAddr::from([192, 0, 2, 64])));
        let tables = &super::super::tables::RUNS;
        let bytes = tables.encode(&run).expect("cbor");
        assert_eq!(tables.decode(&bytes).expect("decode"), run);
        // A row written before the window reads without one; a bound window round-trips.
        run.window = Some(RunWindow {
            started_by: "admin".to_owned(),
            started_at: at,
            mirrors: vec![WindowMirror {
                mirror: MirrorId::generate(),
                hash: HexBytes(vec![7; 32]),
            }],
        });
        let bytes = tables.encode(&run).expect("cbor");
        assert_eq!(tables.decode(&bytes).expect("decode"), run);
        let json = serde_json::to_value(&run).expect("json");
        assert_eq!(json["window"]["mirrors"][0]["hash"], "07".repeat(32));
    }
}
