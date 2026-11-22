//! The approval record, its table and the bodies of the approval routes.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use tenko_core::{
    ApprovalId, AuthStrength, DelegationId, MirrorId, SessionId, Timestamp, UserId,
    dns::{DnsName, is_host_label},
    migrate::plan::TakeoverPlan,
    net::Fqdn,
    table::TableDef,
};
use utoipa::ToSchema;

use super::PENDING_LIFETIME;
use crate::service::SecretString;

/// Approvals by id: what is counted and compared, without the plan.
pub const APPROVALS: TableDef<ApprovalId, ApprovalRecord> = TableDef::new("auth.approvals");
/// The plan of each approval, by its id: read only for the one approval a step names.
pub const APPROVAL_PLANS: TableDef<ApprovalId, TakeoverPlan> = TableDef::new("auth.approval_plans");

/// The characters Windows refuses in an account name, and those that could pass for markup
/// where the name is shown.
const REFUSED_IN_ACCOUNT: &[char] = &[
    '"', '/', '\\', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>', '&',
];

/// What an approval is for: one purpose today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    /// The Windows takeover script (ADR 0038).
    WindowsTakeover,
}

/// What the script reports about itself, shown to the person labeled as reported and as text
/// only. Bounded, and without control or invisible formatting characters, so that no
/// direction mark reaches the page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalClient {
    /// The machine's name: a `NetBIOS` or DNS label.
    pub machine: String,
    /// The Windows user: `DOMAIN\sAMAccountName`.
    pub user: String,
    /// The script's version.
    pub version: String,
}

impl ApprovalClient {
    /// Checks the bounds: the machine a host label of at most 63 characters; the user a
    /// `NetBIOS` domain of at most 15 characters, a backslash and an account name of 1 to 20
    /// characters (spaces and letters of any script allowed) without a control or formatting
    /// character, a space at either end, or a character Windows refuses there; the version 1 to
    /// 32 letters, digits, `.`, `+` or `-`.
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        let word = |text: &str, max: usize, extra: &[u8]| {
            !text.is_empty()
                && text.len() <= max
                && text
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
        };
        if !is_host_label(&self.machine) {
            return Err("client.machine: not a host label");
        }
        let valid_user = self.user.split_once('\\').is_some_and(|(domain, account)| {
            domain.len() <= 15
                && is_host_label(domain)
                && account.chars().count() <= 20
                && crate::client_cert::valid_label(account)
                && !account.contains(REFUSED_IN_ACCOUNT)
        });
        if !valid_user {
            return Err("client.user: not DOMAIN\\account");
        }
        if !word(&self.version, 32, b".+-") {
            return Err("client.version: not a version");
        }
        Ok(())
    }
}

/// `POST /auth/approvals`: a script's request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    /// What the approval is for.
    pub purpose: Purpose,
    /// The plan of the run, which fixes everything the run may create or change.
    pub plan: TakeoverPlan,
    /// The script's P-256 public key, the 65-octet uncompressed point in base64url.
    pub key: String,
    /// What the script reports about itself.
    pub client: ApprovalClient,
}

/// The answer to a request: the id and the nonce the collect signs; nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ApprovalTicket {
    /// The approval's id, hyphenated lower case.
    #[schema(value_type = String, format = Uuid)]
    pub id: ApprovalId,
    /// 32 random octets in base64url.
    pub nonce: String,
}

/// `POST /auth/approvals/lookup` and `POST /auth/approvals/{id}/approve`: the code the person
/// typed, `XXXX-XXXX-XXXX-XXXX` (case, spaces and hyphens do not matter).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeEntry {
    /// The code.
    pub code: SecretString,
}

/// `POST /auth/approvals/clear`: which approvals to deny.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ClearApprovals {
    /// Only those from this address's source (the address, an IPv4-mapped IPv6 address as
    /// its IPv4 address, or its IPv6 /64); all when absent. Anything but an address is
    /// refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub source: Option<IpAddr>,
}

/// The answer to `POST /auth/approvals/clear`: how many of each kind were denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ClearedApprovals {
    /// Waiting requests.
    pub waiting: usize,
    /// Approvals the script had not collected yet.
    pub approved: usize,
}

/// `POST /auth/approvals/{id}/collect`: the nonce signed with the script's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CollectRequest {
    /// ECDSA P-256 with SHA-256 over [`super::collect_message`], `r` and `s` as 32 octets
    /// each (64 octets), base64url.
    pub signature: String,
}

/// The answer to a collect, given once: the delegated session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DelegatedSession {
    /// The bearer secret (`tnka_…`), for `Authorization: Bearer` only.
    pub secret: SecretString,
    /// The session's id, as the session list shows it.
    #[schema(value_type = String, format = Uuid)]
    pub session: SessionId,
    /// The run it acts for.
    #[schema(value_type = String, format = Uuid)]
    pub delegation: DelegationId,
    /// Its deadline, on Tenko's clock; the idle limit ends it earlier.
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: Timestamp,
    /// The idle limit in seconds: a request at least this often keeps it alive.
    pub idle_secs: u64,
}

/// The state of an approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    /// Waiting for the person.
    Pending,
    /// Approved, waiting for the collect.
    Approved(Decision),
    /// Denied.
    Denied {
        /// Who denied it.
        by: UserId,
        /// When.
        at: Timestamp,
    },
    /// Collected: the delegated session exists or existed.
    Consumed {
        /// The approval.
        decision: Decision,
        /// The delegated session.
        session: SessionId,
        /// When it was collected.
        at: Timestamp,
    },
}

/// A person's approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// The approver, whose session the delegated session is.
    pub by: UserId,
    /// The approver's session.
    pub session: SessionId,
    /// Its strength, which the delegated session carries.
    pub strength: AuthStrength,
    /// When.
    pub at: Timestamp,
    /// The run the delegated session acts for.
    pub delegation: DelegationId,
    /// The approver's sessions generation at the approval: ending every session of the
    /// account, or a password change, before the collect refuses it.
    pub generation: u64,
}

/// An approval (`auth.approvals`). It holds no secret: the key is public, the nonce proves
/// nothing without the key, and the delegated session's secret is stored only as the hash of
/// `auth.sessions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// The id.
    pub id: ApprovalId,
    /// What it is for.
    pub purpose: Purpose,
    /// The plan's domain (the plan itself is in [`APPROVAL_PLANS`]).
    pub domain: DnsName,
    /// SHA-256 of the request body as sent.
    pub plan_hash: [u8; 32],
    /// The script's public key, 65 octets.
    pub key: Vec<u8>,
    /// The nonce the collect signs, 32 octets.
    pub nonce: Vec<u8>,
    /// What the script reported.
    pub client: ApprovalClient,
    /// The source address of the request: the only address the collect and the delegated
    /// session are accepted from.
    pub source: IpAddr,
    /// The state.
    pub state: ApprovalState,
    /// When the request arrived.
    pub created_at: Timestamp,
    /// The mirrors the delegated session created, each with the plan's DHCP server it is
    /// named for: one per server.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mirrors: Vec<(Fqdn, MirrorId)>,
}

impl ApprovalRecord {
    /// Whether a pending or approved approval's time is over at `now`: ten minutes after the
    /// request, or a clock that stands before the request ([`crate::clock::stands_before`]).
    pub fn expired(&self, now: Timestamp) -> bool {
        crate::clock::stands_before(now, self.created_at)
            || now.saturating_since(self.created_at) >= PENDING_LIFETIME
    }

    /// Whether it waits for the person at `now`.
    pub fn pending(&self, now: Timestamp) -> bool {
        matches!(self.state, ApprovalState::Pending) && !self.expired(now)
    }

    /// What the person reads, with the approval's plan.
    pub fn view(&self, plan: TakeoverPlan, now: Timestamp) -> ApprovalView {
        ApprovalView {
            id: self.id,
            purpose: self.purpose,
            plan,
            reported: self.client.clone(),
            source: self.source.to_string(),
            created_at: self.created_at,
            expires_at: self
                .created_at
                .checked_add(PENDING_LIFETIME)
                .unwrap_or(self.created_at),
            state: match &self.state {
                ApprovalState::Pending | ApprovalState::Approved(_) if self.expired(now) => {
                    "expired"
                }
                ApprovalState::Pending => "pending",
                ApprovalState::Approved(_) => "approved",
                ApprovalState::Denied { .. } => "denied",
                ApprovalState::Consumed { .. } => "consumed",
            }
            .to_owned(),
        }
    }
}

/// An approval as the person reads it before approving.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ApprovalView {
    /// The id.
    #[schema(value_type = String, format = Uuid)]
    pub id: ApprovalId,
    /// What it is for.
    pub purpose: Purpose,
    /// The plan in full.
    pub plan: TakeoverPlan,
    /// The machine, the Windows user and the version, as the script reported them: shown
    /// labeled as reported, as text.
    pub reported: ApprovalClient,
    /// The source address of the request.
    pub source: String,
    /// When the request arrived.
    #[schema(value_type = String, format = DateTime)]
    pub created_at: Timestamp,
    /// When it expires unless collected.
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: Timestamp,
    /// `pending`, `approved`, `denied`, `consumed` or `expired`.
    pub state: String,
}
