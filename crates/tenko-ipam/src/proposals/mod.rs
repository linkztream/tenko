//! Proposals (IPAM-15, ADR 0005 decision 6): what the reconciler suggests when observation
//! and intent disagree, and the decisions on them.
//!
//! A proposal ([`IntentProposal`]) has a kind, a subject, the observations behind it
//! (evidence), the [`IpamCommand`](crate::IpamCommand)s that would resolve it (the planner
//! previews them like any change), a severity and a state: `open`, `accepted` (approved by
//! a person or adopted by a policy), `rejected`, `expired` (the observation no longer
//! holds) or `superseded` (a newer proposal about the same subject replaced it). At most
//! one proposal per subject key is open at a time (`ipam.proposal_keys`).
//!
//! Observations never become intent by themselves: a person approves ([`decide::approve`])
//! or a prefix's adoption policy adopts ([`adoption`]); both run the commands through the
//! planner and an inline job, with the proposal's new state in the same batch. A rejection
//! ([`decide::reject`]) is remembered with the proposal's fingerprint, so the same evidence
//! does not open the subject again until it changes.
//!
//! # Tables
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `ipam.proposals` | `ProposalId` | [`IntentProposal`] |
//! | `ipam.proposal_keys` | subject key | the open `ProposalId` |
//! | `ipam.proposal_rejections` | subject key | [`Rejection`] |
//! | `ipam.adoption` | `PrefixId` | [`StoredPolicy`] |

pub mod adoption;
pub mod decide;
pub mod keep;
pub mod model;
pub mod query;
pub(crate) mod sync;

pub use adoption::{PolicyView, policy_view, set_policy};
pub use decide::{Decision, approve, clean_reason, current_commands, reject};
pub use keep::keep;
pub use model::{
    AdoptionMode, AdoptionPolicy, IntentProposal, IntentProposalKind, IntentProposalState,
    KeptConflict, ProposalEvidence, ProposalSeverity, ProposalSubject, Rejection, StoredPolicy,
    actions, codes,
};
pub use query::{ProposalPage, ProposalQuery};
