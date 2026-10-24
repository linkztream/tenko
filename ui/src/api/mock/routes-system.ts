// First-run setup, health and system status. Jobs live in routes-jobs.ts; search is served
// with the IPAM routes.
import { http, type HttpHandler } from "msw";
import type { NodeRole, SetupResult, SetupState, SystemDiagnostics, SystemStatus, TlsMode } from "../types";
import { NODE_ROLES, PROFILES } from "../types";
import { appendAudit } from "./audit-store";
import { passwordStrength, requireSession, sessionInfo, startSession } from "./auth";
import { commit, db, isAdmin, type MockUser } from "./db";
import { MOCK_CA_FINGERPRINT, MOCK_VERSION } from "./fixtures";
import { dataFormatStatus, dataFormatWarnings } from "./cluster-store";
import { clusterStatus, clusterWarnings } from "./nodes-store";
import { checkPassword } from "./policy";
import { banner, profileSettings } from "./profiles";
import { Problem, fail, ok } from "./reply";
import { route } from "./route";
import { modulesWarnings, statusModules } from "./routes-updates";
import { tlsWarnings } from "./routes-tls";
import { iso, randomId, uuidHandle } from "./util";
import {
  failPolicy,
  isRecord,
  normalizeHostName,
  oneOf,
  optBool,
  optString,
  reqString,
  validDisplayName,
  validLanguage,
  validUserName,
} from "./validate";

// ---------------------------------------------------------------------------------
// Setup

const getSetup = route("get", "/api/v1/setup", () => {
  if (!db.setupOpen) return ok<SetupState>({ open: false });
  return ok<SetupState>({
    open: true,
    profiles: PROFILES.map((profile) => {
      const settings = profileSettings(profile);
      return { profile, settings, banner: banner(settings) };
    }),
    node: structuredClone(db.node),
  });
});

const TLS_MODES: readonly TlsMode[] = ["internal_ca", "imported", "reverse_proxy", "plain"];

/** Setup tokens compare without dashes, spaces and case. */
function sameToken(a: string, b: string): boolean {
  const normal = (s: string) => s.replace(/[^0-9a-z]/gi, "").toUpperCase();
  return normal(a) === normal(b);
}

const completeSetup = route("post", "/api/v1/setup", async (ctx) => {
  if (!db.setupOpen) return fail("auth.setup.closed");
  // The document's request plus the wizard's proposed extras (tls, roles, accept_slow_disk).
  const body = (await ctx.body()) as Awaited<ReturnType<typeof ctx.body>> & {
    tls?: unknown;
    roles?: unknown;
    accept_slow_disk?: unknown;
  };

  if (typeof body.setup_token !== "string" || !sameToken(body.setup_token, db.setupToken)) {
    return fail("auth.setup.token_invalid");
  }
  const hostInput = reqString(body, "host_name");
  const hostName = normalizeHostName(hostInput);
  if (hostName === null) return fail("auth.setup.invalid_host_name", { params: { host_name: hostInput.trim() } });

  const profile = oneOf(body.profile, PROFILES, "profile");
  if (!isRecord(body.admin)) return fail("sys.invalid_request", { detail: "admin must be an object" });
  const name = validUserName(reqString(body.admin, "name", "admin.name"), "admin.name");
  const displayName = validDisplayName(optString(body.admin, "display_name", "admin.display_name"), name, "admin.display_name");
  const password = reqString(body.admin, "password", "admin.password");
  const language = validLanguage(optString(body, "language") ?? "en");

  let tlsMode: TlsMode = "internal_ca";
  let trustedProxies: string[] = [];
  if (isRecord(body.tls)) {
    tlsMode = oneOf(body.tls.mode, TLS_MODES, "tls.mode");
    if (Array.isArray(body.tls.trusted_proxies)) {
      trustedProxies = body.tls.trusted_proxies.filter((p): p is string => typeof p === "string");
    }
  }
  let roles: NodeRole[] = [...NODE_ROLES];
  if (Array.isArray(body.roles)) {
    roles = body.roles.map((r) => oneOf<NodeRole>(r, NODE_ROLES, "roles"));
  }
  optBool(body, "accept_slow_disk");

  const settings = profileSettings(profile);
  const check = checkPassword(password, {
    policy: settings.password_policy,
    breach: settings.breach_check,
    userName: name,
    displayName,
    hostName,
  });
  if (!check.acceptable) failPolicy("admin.password", check.violations);

  const id = randomId();
  const user: MockUser = {
    id,
    name,
    display_name: displayName,
    roles: ["admin"],
    disabled: false,
    break_glass: false,
    lock: null,
    password,
    totp: false,
    credentials: [],
    recovery_codes: [],
    password_change_required: false,
    language: null,
    created_at: iso(Date.now()),
    last_login_at: null,
    revision: db.revision,
    handle: uuidHandle(id),
  };
  db.users = [user];
  db.settings = settings;
  db.installation = { host_name: hostName, language, tls: { mode: tlsMode, trusted_proxies: trustedProxies }, roles };
  db.setupOpen = false;
  // A fresh installation has no other sessions to show.
  db.seededSessionUsers.add(user.id);
  commit("admin", { objects: [{ kind: "user", id }], tables: ["auth.users", "auth.settings", "sys.installation"] }, [user]);
  db.settingsRevision = db.revision;

  const session = startSession(user, passwordStrength(settings));
  const caFingerprint = tlsMode === "internal_ca" ? MOCK_CA_FINGERPRINT : null;
  // The document answers with the session; the fingerprint is a proposed extra.
  const result: SetupResult = { ...sessionInfo(session, user), ca_fingerprint: caFingerprint };
  return ok(result);
});

// ---------------------------------------------------------------------------------
// Health and status

const health = route("get", "/api/v1/health", () => ok({ status: "ok", version: MOCK_VERSION }));

const ready = route("get", "/api/v1/health/ready", () => ok({ status: "ready", revision: db.revision }));

const systemStatus = route("get", "/api/v1/system/status", () => {
  const { user } = requireSession();
  const now = Date.now();
  const tls = db.installation.tls;
  const warnings: SystemStatus["warnings"] = [];
  if (tls.mode === "plain") {
    warnings.push({
      code: "sys.tls.plain_http",
      detail: "The API and the web UI are served over plain HTTP.",
      params: {},
    });
  }
  // The modules this installation runs, and a pending change of them, are for administrators.
  const admin = isAdmin(user);
  if (admin) warnings.push(...modulesWarnings(), ...tlsWarnings());
  // Nodes that share no protocol major with this controller (docs/cluster.md, section 5).
  warnings.push(...clusterWarnings(), ...dataFormatWarnings());
  return ok<SystemStatus>({
    ...(admin ? { modules: statusModules() } : {}),
    version: MOCK_VERSION,
    started_at: iso(db.startedAt),
    uptime_seconds: Math.max(0, Math.floor((now - db.startedAt) / 1000)),
    node: { id: 1, roles: [...db.installation.roles] },
    store: {
      role: "leader",
      leader: 1,
      revision: db.revision,
      lag: 0,
      audit_head: db.revision,
      data_bytes: 4_800_000,
      disk_bytes: 12_600_000,
      journal_len: Math.min(db.journal.length, 256),
      journal_oldest: db.journal[0]?.id ?? null,
    },
    tls: {
      mode: tls.mode,
      trusted_proxies: [...tls.trusted_proxies],
      hsts: db.settings.profile === "hardened",
      proxy_protocol: false,
      min_version: tls.mode === "internal_ca" || tls.mode === "imported" ? "1.2" : null,
      certificate: null,
    },
    ui: { stub: false, from_directory: false },
    cluster: clusterStatus(),
    data_format: dataFormatStatus(),
    warnings,
  });
});

// ---------------------------------------------------------------------------------
// CA root (WP1.8b; not in the document yet, so a plain msw handler)

/** A placeholder PEM block: the text "test certificate of the mock" in base64, no real certificate. */
export const MOCK_CA_ROOT_PEM = [
  "-----BEGIN CERTIFICATE-----",
  "dGVzdCBjZXJ0aWZpY2F0ZSBvZiB0aGUgbW9jaw==",
  "-----END CERTIFICATE-----",
  "",
].join("\n");

const caRoot = http.get("/api/v1/system/ca-root", () => {
  if (db.setupOpen || db.installation.tls.mode !== "internal_ca") {
    return new Problem("tls.no_internal_ca", {
      status: 404,
      detail: "this installation does not run the internal CA",
    }).reply.toResponse();
  }
  return new Response(MOCK_CA_ROOT_PEM, {
    status: 200,
    headers: { "content-type": "application/x-pem-file", "content-disposition": "attachment; filename=\"tenko-ca-root.pem\"" },
  });
});

// ---------------------------------------------------------------------------------
// Diagnostics for a bug report: the fields of the document and the text the UI shows, with
// the placeholders the server's redaction leaves (RFC 5737, RFC 3849, example.test).

/** The log lines of the mock node, already redacted as the server does it. */
const MOCK_LOG_TAIL = [
  "2026-10-23T09:58:12.104Z  WARN tenko_dns::zone: zone zone-1.example.test: transfer from 192.0.2.1 refused (TSIG unknown key)",
  "2026-10-23T10:02:40.511Z  WARN tenko_dhcp::lease: 192.0.2.2 declined by 00-00-5e-00-00-01; the address is held for 10 minutes",
  "2026-10-23T10:05:01.000Z ERROR tenko_api::routes::backup: scheduled backup failed: the target directory is not writable",
];

/** The text of the document, as `GET /system/diagnostics` renders it. */
export function renderDiagnostics(document: Omit<SystemDiagnostics, "text">): string {
  const lines = [
    "Tenko DDI diagnostics",
    "Redacted before leaving the node: addresses, host names, zone names and account names are placeholders (RFC 5737, RFC 3849, RFC 7042, example.test), numbered in order of first appearance.",
    "",
    `version: ${document.version} (API ${document.api_version})`,
    `platform: ${document.os} ${document.arch}`,
    `profile: ${document.profile}`,
    `roles: ${document.roles.length > 0 ? document.roles.join(", ") : "none"}`,
    `modules: ${document.modules.length > 0 ? document.modules.join(", ") : "none"}`,
    `uptime: ${uptimeText(document.uptime_seconds)} (${document.uptime_seconds} s)`,
  ];
  if (document.findings.length === 0) lines.push("findings: none");
  else {
    lines.push(`findings: ${document.findings.length}`);
    for (const finding of document.findings) lines.push(`  ${finding.severity.padEnd(8)} ${finding.code}`);
  }
  if (document.log.length === 0) lines.push("log: no line at warn level or above since the start");
  else {
    lines.push(`log: last ${document.log.length} line(s) at warn level or above, redacted`);
    for (const line of document.log) lines.push(`  ${line}`);
  }
  return `${lines.join("\n")}\n`;
}

function uptimeText(seconds: number): string {
  const days = Math.floor(seconds / 86_400);
  const pad = (n: number) => String(n).padStart(2, "0");
  const clock = `${pad(Math.floor((seconds % 86_400) / 3600))}:${pad(Math.floor((seconds % 3600) / 60))}:${pad(seconds % 60)}`;
  return days > 0 ? `${days}d ${clock}` : clock;
}

const systemDiagnostics = route("get", "/api/v1/system/diagnostics", () => {
  requireSession();
  const findings: SystemDiagnostics["findings"] = [];
  if (db.installation.tls.mode === "plain") findings.push({ code: "sys.tls.plain_http", severity: "warning" });
  for (const warning of [...modulesWarnings(), ...clusterWarnings(), ...dataFormatWarnings()]) {
    findings.push({ code: warning.code, severity: "warning" });
  }
  const document: Omit<SystemDiagnostics, "text"> = {
    version: MOCK_VERSION,
    api_version: MOCK_VERSION,
    os: "linux",
    arch: "x86_64",
    profile: db.settings.profile,
    roles: [...db.installation.roles],
    modules: statusModules(),
    uptime_seconds: Math.max(0, Math.floor((Date.now() - db.startedAt) / 1000)),
    findings,
    log: [...MOCK_LOG_TAIL],
  };
  appendAudit({ action: "sys.diagnostics", objects: [{ kind: "system", id: "00000000-0000-0000-0000-000000000000" }] });
  return ok<SystemDiagnostics>({ ...document, text: renderDiagnostics(document) });
});

export const systemRoutes: HttpHandler[] = [getSetup, completeSetup, health, ready, systemStatus, systemDiagnostics, caRoot];
