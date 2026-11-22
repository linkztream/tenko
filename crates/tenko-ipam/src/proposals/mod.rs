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
//! # What the tables keep
//!
//! - A proposal that the reconciler closes itself (it expired, or a newer one replaces it)
//!   is deleted, not kept closed, whatever its kind: it carries no person's decision, the
//!   facts keep what it was about visible, and sources that report what a client invents
//!   would otherwise fill the disk. The `expired` and `superseded` states remain for the
//!   rows earlier versions wrote.
//! - While the clock guard holds expiry, the open discovered hosts of a network never
//!   outnumber its assignable addresses, and those outside every IPv4 network that no
//!   current sighting stands for are held to the number of distinct MAC addresses the
//!   facts name, so those whose facts were overwritten leave; the oldest sightings go
//!   first, and a device that is present never goes.
//! - A decided proposal, and a closed row an earlier version wrote, is deleted once its last
//!   change is older than the fact retention, on the reconciler's purge timer; a remembered
//!   rejection stays.
//!
//! Each of these removals that no new proposal replaces is a batch that only deletes, with
//! one audit record that counts what it removed.
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
pub(crate) mod purge;
pub mod query;
pub(crate) mod sync;

pub use adoption::{PolicyView, policy_view, set_policy};
pub use decide::{
    ApproveRequest, Decision, Remember, approve, approve_with, clean_reason, current_commands,
    reject,
};
pub use keep::keep;
pub use model::{
    AdoptionMode, AdoptionPolicy, IntentProposal, IntentProposalKind, IntentProposalState,
    KeptConflict, NameChoice, NameChoiceSource, ProposalEvidence, ProposalSeverity,
    ProposalSubject, Rejection, StoredPolicy, actions, codes,
};
pub use query::{ProposalPage, ProposalQuery};
