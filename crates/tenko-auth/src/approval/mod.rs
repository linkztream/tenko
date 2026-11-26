//! Approvals of a takeover script (ADR 0038, `docs/plans/windows-takeover-plan.md` section
//! 2.16.2): the device-style grant through which a signed-in administrator lets a script on a
//! Windows machine act for one run, as a delegated session ([`crate::delegation`]).
//!
//! 1. The script sends its plan and a P-256 public key made in memory, without a credential
//!    (`POST /auth/approvals`). Tenko checks the request against its own limits
//!    ([`parse_request`]) and answers with an id and a nonce.
//! 2. Both sides compute the [`code`] over the domain, the SHA-256 of the TLS root, the
//!    SHA-256 of the request as sent (which carries the plan), the key and the id. A script
//!    that reached Tenko through an interceptor computed it over another root and cannot match.
//! 3. The person types the code (`lookup`), reads the plan and approves with a sign-in within
//!    the last five minutes (`approve`); the code is compared in constant time with the code
//!    of every pending approval, and a code that matches two is refused.
//! 4. The script collects once, signing [`collect_message`] with its key (`collect`): the
//!    answer is the delegated session's secret, and the approval is consumed.
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `auth.approvals` | [`ApprovalId`](tenko_core::ApprovalId) | [`ApprovalRecord`], without the plan |
//! | `auth.approval_plans` | [`ApprovalId`](tenko_core::ApprovalId) | its plan |
//!
//! Neither table sends events: a request without a credential never reaches an
//! administrator's open page.
//!
//! # Bounds
//!
//! A request body is at most [`MAX_REQUEST_BYTES`]; a plan that parses holds at most the item
//! counts of `tenko_core::migrate::plan`. At most [`MAX_PENDING_PER_SOURCE`] pending approvals
//! per source (an IPv4 address or an IPv6 /64) and [`MAX_PENDING`] in all, each pending for
//! [`PENDING_LIFETIME`]; one request per address every [`REQUEST_SPACING`] on each controller.
//! A request decodes the small rows of `auth.approvals` only, never a plan. An administrator
//! denies every waiting request and uncollected approval, or those of one source, in one
//! step, and is told how many of each kind.
//!
//! The authentication service's sweep removes the rows that are over every
//! [`PENDING_LIFETIME`]: a consumed approval once its delegated session can no longer live
//! ([`crate::delegation::LIFETIME`] after the collect), every other one once its pending time
//! is over. It removes a row only when this controller's clock stands that far after the
//! row's time, never on a clock that stands before it, and nothing while the clock guard
//! holds ([`tenko_core::clock::trusted_now`]). Outside such a hold, a row that is not consumed
//! is therefore stored for at most two pending lifetimes (20 minutes), and the requests of any
//! ten minutes number at most [`MAX_PENDING`] (each still waits at their end unless a person
//! decided it). Stored, that is at most 2 × 64 = 128 plans of at most 64 KiB, 8 MiB, and
//! 2 × 2 = 4 of one source; each request a person denies or approves lets one more in for
//! those 20 minutes, so a denial of every waiting request lets up to 64 more in. Beside them,
//! one consumed approval per delegated session alive, which a person's approval and the rule
//! of one run per domain bound.
//!
//! The times of an approval are stored wall-clock times, because any controller may serve its
//! steps; a controller whose clock stands more than [`tenko_core::clock::TOLERANCE`] before a
//! stored time treats the approval as over for its steps, and while the clock guard holds
//! issuing the lookup, the approval and the collect are refused with
//! [`Refusal::ClockHeld`]: an administrator confirms the clock first.

mod code;
mod model;
mod pace;
mod plan;

use std::{collections::BTreeMap, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub use code::{
    CODE_CONTEXT, COLLECT_CONTEXT, canonical_code, code, collect_message, verify_collect,
};
pub use model::{
    APPROVAL_PLANS, APPROVALS, ApprovalClient, ApprovalRecord, ApprovalRequest, ApprovalState,
    ApprovalTicket, ApprovalView, ClearApprovals, ClearedApprovals, CodeEntry, CollectRequest,
    Decision, DelegatedSession, Purpose,
};
pub(crate) use pace::Paces;
pub use plan::check_plan;

/// The largest request body, in octets.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// How long an approval waits for the person and the collect.
pub const PENDING_LIFETIME: Duration = Duration::from_secs(600);
/// Pending approvals per source.
pub const MAX_PENDING_PER_SOURCE: usize = 2;
/// Pending approvals in all.
pub const MAX_PENDING: usize = 64;
/// The least time between two requests of one address.
pub const REQUEST_SPACING: Duration = Duration::from_secs(10);
/// How often the requests of one source, and the wrong codes of one browser session, are
/// audited: once in this time, the rest counted in memory.
pub const AUDIT_EVERY: Duration = Duration::from_secs(60);
/// Wrong codes from one browser session within [`WRONG_CODE_WINDOW`] that lock its lookups.
pub const WRONG_CODES: u32 = 5;
/// The window of [`WRONG_CODES`].
pub const WRONG_CODE_WINDOW: Duration = Duration::from_secs(600);
/// How long a browser session's lookups stay locked after its fifth wrong code.
pub const LOOKUP_LOCK: Duration = Duration::from_secs(600);
/// The prefix length that makes one IPv6 source: a host may hold many addresses of its /64.
pub const IPV6_SOURCE_PREFIX: u8 = 64;

/// The audit actions of approvals.
pub mod actions {
    use tenko_core::audit::AuditAction;

    /// A script asked for an approval (at most one record a minute per source).
    pub const REQUEST: AuditAction = AuditAction::from_static("auth.approval.request");
    /// A person approved a script's request.
    pub const APPROVE: AuditAction = AuditAction::from_static("auth.approval.approve");
    /// A person denied a script's request.
    pub const DENY: AuditAction = AuditAction::from_static("auth.approval.deny");
    /// A script collected its delegated session.
    pub const COLLECT: AuditAction = AuditAction::from_static("auth.approval.collect");
    /// A code that matched nothing, or a collect that failed its source or signature (at
    /// most one record a minute per browser session or source).
    pub const REFUSE: AuditAction = AuditAction::from_static("auth.approval.refuse");
    /// A delegated session's request was refused (at most one record a minute per session
    /// and outcome).
    pub const DELEGATION_REFUSE: AuditAction = AuditAction::from_static("auth.delegation.refuse");
}

/// Why an approval step was refused. Codes `auth.approval.*`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// No such approval, or not from this source.
    #[error("no such approval")]
    NotFound,
    /// The approval waited longer than ten minutes.
    #[error("the approval has expired; start the script again")]
    Expired,
    /// The code matches no pending approval.
    #[error("the code matches no waiting approval")]
    Code,
    /// The code matches more than one pending approval.
    #[error("the code matches more than one waiting approval; start the scripts again")]
    Ambiguous,
    /// A bound was reached: requests of one source, pending approvals, locked lookups, one
    /// run per domain, or an unknown source.
    #[error("too many approvals or attempts: {0}")]
    Limit(&'static str),
    /// The collect's signature does not verify with the request's key.
    #[error("the signature does not verify")]
    Signature,
    /// The approval was collected before.
    #[error("the approval was collected before")]
    Consumed,
    /// The request does not meet Tenko's limits on the plan; `reason` says which.
    #[error("the request was refused: {0}")]
    Plan(String),
    /// The person has not decided yet.
    #[error("the approval waits for a person")]
    Pending,
    /// The person denied it.
    #[error("the approval was denied")]
    Denied,
    /// The clock guard holds issuing on this controller.
    #[error("this controller's clock is held: an administrator confirms the clock first")]
    ClockHeld,
}

impl Refusal {
    /// The stable code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "auth.approval.not_found",
            Self::Expired => "auth.approval.expired",
            Self::Code => "auth.approval.code",
            Self::Ambiguous => "auth.approval.ambiguous",
            Self::Limit(_) => "auth.approval.limit",
            Self::Signature => "auth.approval.signature",
            Self::Consumed => "auth.approval.consumed",
            Self::Plan(_) => "auth.approval.plan",
            Self::Pending => "auth.approval.pending",
            Self::Denied => "auth.approval.denied",
            Self::ClockHeld => "auth.approval.clock_held",
        }
    }

    /// The HTTP status.
    pub const fn http_status(&self) -> u16 {
        match self {
            Self::NotFound => 404,
            Self::Expired => 410,
            Self::Code | Self::Denied | Self::Signature => 403,
            Self::Ambiguous | Self::Consumed | Self::Pending => 409,
            Self::Limit(_) => 429,
            Self::Plan(_) => 422,
            Self::ClockHeld => 503,
        }
    }

    /// The parameters of the problem details.
    pub fn params(&self) -> BTreeMap<&'static str, String> {
        match self {
            Self::Limit(what) => BTreeMap::from([("limit", (*what).to_owned())]),
            Self::Plan(reason) => BTreeMap::from([("reason", reason.clone())]),
            _ => BTreeMap::new(),
        }
    }
}

impl From<Refusal> for crate::AuthError {
    fn from(refusal: Refusal) -> Self {
        Self::Approval(refusal)
    }
}

/// The bucket of a source address: an IPv4 address (an IPv4-mapped IPv6 address is that), or
/// the /64 of an IPv6 address.
pub fn source_bucket(source: std::net::IpAddr) -> Vec<u8> {
    match source.to_canonical() {
        std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
        std::net::IpAddr::V6(v6) => v6.octets()[..usize::from(IPV6_SOURCE_PREFIX / 8)].to_vec(),
    }
}

/// Parses and checks the body of `POST /auth/approvals`, untrusted input from the network:
/// at most [`MAX_REQUEST_BYTES`], one JSON object of strict types (unknown and duplicate
/// fields refused), the client's reported names within their bounds, the key a P-256 point,
/// and the plan within Tenko's limits ([`check_plan`]). Answers the request, the key's 65
/// octets and the SHA-256 of the body as sent.
///
/// # Errors
///
/// [`Refusal::Plan`] with the reason; never a part of the body.
pub fn parse_request(body: &[u8]) -> Result<(ApprovalRequest, Vec<u8>, [u8; 32]), Refusal> {
    let request: ApprovalRequest = strict_json(body)?;
    request.client.check().map_err(plan_refusal)?;
    let key = URL_SAFE_NO_PAD
        .decode(&request.key)
        .ok()
        .filter(|key| key.len() == 65 && key[0] == 0x04)
        .filter(|key| {
            aws_lc_rs::signature::ParsedPublicKey::new(
                &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED,
                key,
            )
            .is_ok()
        })
        .ok_or_else(|| plan_refusal("key: not an uncompressed P-256 point in base64url"))?;
    check_plan(&request.plan).map_err(plan_refusal)?;
    let hash = <sha2::Sha256 as sha2::Digest>::digest(body).into();
    Ok((request, key, hash))
}

/// Parses the body of `POST /auth/approvals/{id}/collect`, untrusted input from the network:
/// one JSON object with a signature of exactly 64 octets in base64url.
///
/// # Errors
///
/// [`Refusal::Signature`] for anything else.
pub fn parse_collect(body: &[u8]) -> Result<[u8; 64], Refusal> {
    let request: CollectRequest = strict_json(body).map_err(|_| Refusal::Signature)?;
    URL_SAFE_NO_PAD
        .decode(&request.signature)
        .ok()
        .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
        .ok_or(Refusal::Signature)
}

/// Refuses while the clock guard holds issuing ([`tenko_core::clock::plausible_now`]): how far
/// a held clock stands from the times of an approval is not known, so nothing is judged by it.
pub(crate) fn clock_plausible() -> Result<(), Refusal> {
    tenko_core::clock::plausible_now()
        .map(drop)
        .map_err(|_| Refusal::ClockHeld)
}

fn plan_refusal(reason: impl Into<String>) -> Refusal {
    Refusal::Plan(reason.into())
}

/// One JSON object within [`MAX_REQUEST_BYTES`]; the reason of a refusal names the position,
/// never the text, so nothing the client sent is echoed.
fn strict_json<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, Refusal> {
    if body.len() > MAX_REQUEST_BYTES {
        return Err(plan_refusal("the body is larger than 64 KiB"));
    }
    if body.trim_ascii_start().first() != Some(&b'{') {
        return Err(plan_refusal("the body must be a JSON object"));
    }
    serde_json::from_slice(body).map_err(|error| {
        plan_refusal(format!(
            "the body does not match the schema at line {}, column {}",
            error.line(),
            error.column()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_have_codes_and_statuses() {
        for (refusal, code, status) in [
            (Refusal::NotFound, "auth.approval.not_found", 404),
            (Refusal::Expired, "auth.approval.expired", 410),
            (Refusal::Code, "auth.approval.code", 403),
            (Refusal::Ambiguous, "auth.approval.ambiguous", 409),
            (Refusal::Limit("source"), "auth.approval.limit", 429),
            (Refusal::Signature, "auth.approval.signature", 403),
            (Refusal::Consumed, "auth.approval.consumed", 409),
            (Refusal::Plan("x".into()), "auth.approval.plan", 422),
        ] {
            assert_eq!(refusal.code(), code);
            assert_eq!(refusal.http_status(), status);
        }
    }

    #[test]
    fn ipv6_sources_share_their_64() {
        let a = source_bucket("2001:db8::1".parse().expect("an address"));
        let b = source_bucket("2001:db8::ffff:1".parse().expect("an address"));
        assert_eq!(a, b);
        assert_ne!(
            a,
            source_bucket("2001:db8:0:1::1".parse().expect("an address"))
        );
        assert_eq!(
            source_bucket("192.0.2.1".parse().expect("an address")).len(),
            4
        );
    }

    #[test]
    fn a_collect_body_is_one_signature_of_64_octets() {
        let signature = URL_SAFE_NO_PAD.encode([7u8; 64]);
        assert_eq!(
            parse_collect(format!(r#"{{"signature":"{signature}"}}"#).as_bytes()),
            Ok([7u8; 64])
        );
        for bad in [
            String::new(),
            "[]".to_owned(),
            format!(r#"{{"signature":"{signature}","x":1}}"#),
            format!(r#"{{"signature":"{}"}}"#, URL_SAFE_NO_PAD.encode([7u8; 63])),
            r#"{"signature":"!!"}"#.to_owned(),
        ] {
            assert_eq!(
                parse_collect(bad.as_bytes()),
                Err(Refusal::Signature),
                "{bad}"
            );
        }
    }
}
