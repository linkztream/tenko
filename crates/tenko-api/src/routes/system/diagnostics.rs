//! `GET /system/diagnostics`: what a bug report needs about this node, redacted before it
//! leaves it (the UI's "Report a bug" dialog and `tenko system diagnostics`).
//!
//! Area: system.
//!
//! The document carries the version, the platform, the security profile, the roles, the
//! modules, the uptime, the active health findings (code and severity only) and the last
//! [`LOG_LINES`] lines of the node's own log at warn level or above. Every IP address, MAC
//! address, host name, zone name and account name in those lines is replaced by a numbered
//! placeholder ([`crate::redact::Redactor`]): the zones of the catalog and the account names
//! of the installation are given to the redactor, so a name the suffix list would miss is
//! still caught. Nothing in the answer names the installation, and nothing is sent anywhere
//! by the node: the person reads the text and files it under their own account.
//!
//! Any signed-in principal that may read the system status may read it, with a session or a
//! personal token (the CLI signs in with a token). Every read is audited as
//! [`AUDIT_ACTION`], and the document is answered only after the record committed.
//!
//! The log lines come from the request extension `Arc<LogTail>`: the server binary feeds it
//! from a warn-filtered layer of its subscriber. Without the extension the document says
//! that the log is not attached.

use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex, PoisonError},
};

use axum::{Extension, Json, extract::State};
use tenko_core::{
    Action,
    audit::{AuditAction, AuditDraft},
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt as _, WriteBatch};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    dto::system::{DiagnosticFinding, FindingSeverity, SystemDiagnostics, SystemStatus},
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    redact::Redactor,
    state::AppState,
};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(system_diagnostics))
}

/// The audit action of every read of the diagnostics (the `sys` namespace of the platform,
/// as `sys.setup.complete` and `sys.backup.create`).
pub const AUDIT_ACTION: &str = "sys.diagnostics";

/// [`AUDIT_ACTION`] as an action; a constant, so an invalid name fails the build.
const ACTION: AuditAction = AuditAction::from_static(AUDIT_ACTION);

/// How many log lines the document carries.
pub const LOG_LINES: usize = 20;

/// How many lines the server keeps for the document: more than it shows, so that a burst of
/// one target does not push everything else out before a report is read.
pub const LOG_TAIL_CAPACITY: usize = 200;

/// The informational findings: states worth knowing when reading a report, nothing to act on.
const INFORMATIONAL: &[&str] = &[
    "sys.ui.stub",
    "dns.trust_anchor.pending",
    "dns.nta.active",
    // WP9.2: advertisements with O and without M (stateless DHCPv6 may be meant), and a
    // check that cannot run.
    tenko_dhcp::ra::OTHER_ONLY,
    tenko_dhcp::ra::UNCHECKED,
];

/// The findings of a role or a service that does not do its work.
const ERRORS: &[&str] = &[
    super::DNS_ROLE_NOT_SERVING,
    super::DHCP_ROLE_NOT_SERVING,
    super::DHCP_ROLE_STORE_REFUSED,
    super::LEADER_SERVICE_FAILING,
    "audit.export.failing",
];

/// The severity of a finding by its code.
pub fn severity_of(code: &str) -> FindingSeverity {
    if INFORMATIONAL.contains(&code) {
        FindingSeverity::Info
    } else if ERRORS.contains(&code) {
        FindingSeverity::Error
    } else {
        FindingSeverity::Warning
    }
}

/// The last lines of the node's log at warn level or above, as the server's subscriber
/// writes them. The server binary adds it as the request extension `Arc<LogTail>` and gives
/// it to a formatting layer as its writer (`&LogTail` is `io::Write`): every write is one
/// formatted line, split at newlines in case a formatter writes several at once.
#[derive(Debug)]
pub struct LogTail {
    state: Mutex<TailState>,
}

#[derive(Debug)]
struct TailState {
    lines: VecDeque<String>,
    capacity: usize,
    /// The start of a line whose end has not been written yet.
    partial: String,
}

impl LogTail {
    /// A tail that keeps the last `capacity` lines.
    pub fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(TailState {
                lines: VecDeque::with_capacity(capacity.min(LOG_TAIL_CAPACITY)),
                capacity: capacity.max(1),
                partial: String::new(),
            }),
        }
    }

    /// Adds one line, dropping the oldest when the tail is full.
    pub fn push(&self, line: &str) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.push(line);
    }

    /// The last `count` lines, oldest first.
    pub fn lines(&self, count: usize) -> Vec<String> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let skip = state.lines.len().saturating_sub(count);
        state.lines.iter().skip(skip).cloned().collect()
    }
}

impl TailState {
    fn push(&mut self, line: &str) {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            return;
        }
        while self.lines.len() >= self.capacity {
            self.lines.pop_front();
        }
        self.lines.push_back(line.to_owned());
    }
}

impl io::Write for &LogTail {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        for piece in text.split_inclusive('\n') {
            if piece.ends_with('\n') {
                let line = if state.partial.is_empty() {
                    piece.to_owned()
                } else {
                    let mut line = std::mem::take(&mut state.partial);
                    line.push_str(piece);
                    line
                };
                state.push(&line);
            } else {
                state.partial.push_str(piece);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The name of a profile as the API serializes it.
fn profile_name(profile: tenko_auth::settings::Profile) -> &'static str {
    use tenko_auth::settings::Profile;
    match profile {
        Profile::Home => "home",
        Profile::Standard => "standard",
        Profile::Hardened => "hardened",
        Profile::Lab => "lab",
    }
}

/// `d h:mm:ss` of a number of seconds.
fn uptime_text(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let secs = seconds % 60;
    if days > 0 {
        format!("{days}d {hours:02}:{minutes:02}:{secs:02}")
    } else {
        format!("{hours:02}:{minutes:02}:{secs:02}")
    }
}

/// The text of the document: every field, one line each, then the findings and the log.
pub fn render(document: &SystemDiagnostics, log_attached: bool) -> String {
    let list = |items: &[String]| {
        if items.is_empty() {
            "none".to_owned()
        } else {
            items.join(", ")
        }
    };
    let mut lines = vec![
        "Tenko DDI diagnostics".to_owned(),
        "Redacted before leaving the node: addresses, host names, zone names and account names \
         are placeholders (RFC 5737, RFC 3849, RFC 7042, example.test), numbered in order of \
         first appearance."
            .to_owned(),
        String::new(),
        format!(
            "version: {} (API {})",
            document.version, document.api_version
        ),
        format!("platform: {} {}", document.os, document.arch),
        format!("profile: {}", document.profile),
        format!("roles: {}", list(&document.roles)),
        format!("modules: {}", list(&document.modules.names())),
        format!(
            "uptime: {} ({} s)",
            uptime_text(document.uptime_seconds),
            document.uptime_seconds
        ),
    ];
    if document.findings.is_empty() {
        lines.push("findings: none".to_owned());
    } else {
        lines.push(format!("findings: {}", document.findings.len()));
        for finding in &document.findings {
            let severity = match finding.severity {
                FindingSeverity::Info => "info",
                FindingSeverity::Warning => "warning",
                FindingSeverity::Error => "error",
            };
            lines.push(format!("  {severity:<8} {}", finding.code));
        }
    }
    if !log_attached {
        lines.push("log: not attached (the server did not provide its log tail)".to_owned());
    } else if document.log.is_empty() {
        lines.push("log: no line at warn level or above since the start".to_owned());
    } else {
        lines.push(format!(
            "log: last {} line(s) at warn level or above, redacted",
            document.log.len()
        ));
        lines.extend(document.log.iter().map(|line| format!("  {line}")));
    }
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// The document from a status, the installation's names and the log lines.
pub(crate) fn document(
    status: SystemStatus,
    profile: tenko_auth::settings::Profile,
    zones: Vec<String>,
    accounts: Vec<String>,
    log: Option<Vec<String>>,
) -> SystemDiagnostics {
    let mut redactor = Redactor::new(zones, accounts);
    let log_attached = log.is_some();
    let log = log
        .unwrap_or_default()
        .iter()
        .map(|line| redactor.redact(line))
        .collect();
    let findings = status
        .warnings
        .iter()
        .map(|warning| DiagnosticFinding {
            code: warning.code.clone(),
            severity: severity_of(&warning.code),
        })
        .collect();
    let mut document = SystemDiagnostics {
        version: status.version,
        api_version: crate::version().to_owned(),
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        profile: profile_name(profile).to_owned(),
        roles: status.node.roles,
        modules: status.modules,
        uptime_seconds: status.uptime_seconds,
        findings,
        log,
        text: String::new(),
    };
    document.text = render(&document, log_attached);
    document
}

#[allow(
    clippy::too_many_arguments,
    reason = "one extractor per part of the status, each optional, as GET /system/status"
)]
#[utoipa::path(
    get,
    path = "/system/diagnostics",
    tag = "system",
    operation_id = "system_diagnostics",
    summary = "Get the diagnostics of a bug report: version, platform, profile, roles, modules, uptime, findings and the redacted log tail",
    responses(
        (status = 200, description = "The diagnostics of this node, redacted", body = SystemDiagnostics),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn system_diagnostics(
    State(state): State<AppState>,
    running: Option<Extension<super::RunningVersion>>,
    leader: Option<Extension<super::LeaderSource>>,
    backup: Option<Extension<Arc<dyn crate::routes::backup::BackupService>>>,
    format: Option<Extension<super::DataFormatSource>>,
    dns: Option<Extension<crate::routes::dns::DnsNodeSlot>>,
    zones: Option<Extension<Arc<tenko_dns::zone::ZoneService>>>,
    dhcp: Option<Extension<crate::routes::dhcp::DhcpNodeSlot>>,
    ipam: Option<Extension<Arc<tenko_ipam::IpamService>>>,
    tail: Option<Extension<Arc<LogTail>>>,
    Ctx(ctx): Ctx,
) -> Result<Json<SystemDiagnostics>, ApiError> {
    state.authorize(&ctx.principal, Action::Read, &super::system_object())?;
    let status = super::assemble(
        &state, ctx.now, running, leader, backup, format, dns, zones, dhcp, ipam,
    )
    .await;
    let view = state.store.read(ReadConsistency::Local).await?;
    let profile = view
        .get_typed(&tenko_auth::model::SETTINGS, &())?
        .map_or(tenko_auth::settings::Profile::Home, |(settings, _)| {
            settings.profile
        });
    let zone_names = tenko_dns::zone::ZoneService::zones(view.as_ref())
        .map(|rows| {
            rows.into_iter()
                .map(|row| row.zone.name.as_str().to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let accounts: Vec<String> = view
        .scan_typed(
            &tenko_auth::model::USERS,
            KeyRange::all(),
            usize::MAX,
            false,
        )?
        .into_iter()
        .map(|(_, user, _)| user.name)
        .collect();
    let log = tail.map(|Extension(tail)| tail.lines(LOG_LINES));
    let document = document(status, profile, zone_names, accounts, log);

    // The record first, the document after it committed (as every audited read).
    let mut batch = WriteBatch::new(ctx.principal.clone(), ctx.now);
    batch.request = Some(ctx.request);
    let mut draft = AuditDraft::success(ACTION, vec![super::system_object()]);
    draft.source_ip = ctx.source_ip;
    batch.audit(draft);
    state.store.propose(batch).await?;
    Ok(Json(document))
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tenko_core::{Principal, SystemComponent, Timestamp};
    use tenko_store::tables;
    use tower::ServiceExt as _;

    use super::*;

    /// The JSON of `GET /system/diagnostics` over `state`, with the tail attached when given.
    async fn get(state: AppState, tail: Option<Arc<LogTail>>) -> (StatusCode, serde_json::Value) {
        let (mut router, _) = crate::api(state);
        if let Some(tail) = tail {
            router = router.layer(Extension(tail));
        }
        let request = Request::get("/api/v1/system/diagnostics")
            .body(Body::empty())
            .expect("request");
        let response = router.oneshot(request).await.expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), 256 * 1024)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
        (status, json)
    }

    #[test]
    fn the_tail_keeps_the_last_lines_and_joins_partial_writes() {
        let tail = LogTail::new(3);
        for n in 1..=4 {
            tail.push(&format!("line {n}\n"));
        }
        assert_eq!(tail.lines(10), vec!["line 2", "line 3", "line 4"]);
        assert_eq!(tail.lines(2), vec!["line 3", "line 4"]);
        let mut writer = &tail;
        writer.write_all(b"partial ").expect("write");
        writer.write_all(b"line\nnext\n").expect("write");
        assert_eq!(tail.lines(2), vec!["partial line", "next"]);
    }

    #[test]
    fn severities_follow_the_code() {
        assert_eq!(severity_of("sys.ui.stub"), FindingSeverity::Info);
        assert_eq!(severity_of("dns.role.not_serving"), FindingSeverity::Error);
        assert_eq!(severity_of("dns.role.lagging"), FindingSeverity::Warning);
    }

    #[tokio::test]
    async fn the_document_is_redacted_and_the_read_is_audited() {
        let state = AppState::default();
        // A zone of the catalog and an administrator, so the redactor knows them.
        let now = Timestamp::now();
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Api), now);
        let zone = tenko_core::dns::Zone {
            id: tenko_core::dns::ZoneId::generate(),
            name: "corp.example.".parse().expect("zone name"),
            kind: tenko_core::dns::ZoneKind::Primary,
            tenant: None,
            scopes: vec![tenko_core::dns::ZoneScope::default_scope()],
            serial: tenko_core::dns::SerialPolicy::default(),
            soa: tenko_core::dns::SoaDefaults::new(
                "ns1.corp.example.".parse().expect("mname"),
                "hostmaster.corp.example.".parse().expect("rname"),
            ),
            transfer: tenko_core::dns::TransferPolicy::default(),
            update: tenko_core::dns::UpdatePolicy::default(),
            dnssec: tenko_core::dns::DnssecPolicy::default(),
            source: None,
            reverse_of: None,
            catalog: false,
            description: None,
            created: tenko_core::ipam::Stamp::new(now, Principal::system(SystemComponent::Api)),
            updated: tenko_core::ipam::Stamp::new(now, Principal::system(SystemComponent::Api)),
        };
        batch
            .put_typed(&tenko_core::dns::tables::ZONES, &zone.id, &zone)
            .expect("encode zone");
        let user = tenko_auth::model::UserRecord::new(
            "alice".to_owned(),
            "Alice".to_owned(),
            Vec::new(),
            now,
        );
        batch
            .put_typed(&tenko_auth::model::USERS, &user.id, &user)
            .expect("encode user");
        state.store.propose(batch).await.expect("seed");

        let tail = Arc::new(LogTail::new(LOG_TAIL_CAPACITY));
        tail.push("WARN tenko_dns: zone www.corp.example at 10.1.2.3 refused alice");
        tail.push("WARN tenko_dns: 10.1.2.3 again");
        let (status, json) = get(state.clone(), Some(Arc::clone(&tail))).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["version"], crate::version());
        assert_eq!(json["os"], std::env::consts::OS);
        assert_eq!(json["profile"], "home");
        let log: Vec<&str> = json["log"]
            .as_array()
            .expect("log")
            .iter()
            .map(|line| line.as_str().expect("line"))
            .collect();
        assert_eq!(
            log,
            vec![
                "WARN tenko_dns: zone host-1.zone-1.example.test at 192.0.2.1 refused user-1",
                "WARN tenko_dns: 192.0.2.1 again",
            ]
        );
        let text = json["text"].as_str().expect("text");
        assert!(text.contains("profile: home\n"), "{text}");
        assert!(text.contains("192.0.2.1 again"), "{text}");
        assert!(
            !text.contains("10.1.2.3") && !text.contains("alice"),
            "{text}"
        );
        for finding in json["findings"].as_array().expect("findings") {
            assert!(finding.get("detail").is_none(), "no detail text: {finding}");
            assert!(finding["severity"].is_string());
        }

        let view = state
            .store
            .read(ReadConsistency::Local)
            .await
            .expect("view");
        let audited = view
            .scan_typed(&tables::AUDIT, KeyRange::all(), usize::MAX, false)
            .expect("audit scan")
            .into_iter()
            .any(|(_, record, _): (_, tenko_core::audit::AuditRecord, _)| {
                record.draft.action.as_str() == AUDIT_ACTION
            });
        assert!(audited, "the read is audited as {AUDIT_ACTION}");
    }

    #[tokio::test]
    async fn without_the_tail_the_document_says_so() {
        let (status, json) = get(AppState::default(), None).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["log"].as_array().map(Vec::len), Some(0));
        assert!(
            json["text"]
                .as_str()
                .expect("text")
                .contains("log: not attached"),
            "{json}"
        );
    }
}
