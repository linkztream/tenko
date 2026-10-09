// First-run setup, health, system status, jobs and search.
import type { HttpHandler } from "msw";
import type { JobState, JobSummary, NodeRole, SetupResult, SetupState, SystemStatus, TlsMode } from "../types";
import { NODE_ROLES, PROFILES } from "../types";
import { passwordStrength, requireSession, sessionInfo, startSession } from "./auth";
import { commit, db, type MockJob, type MockUser } from "./db";
import { MOCK_CA_FINGERPRINT, MOCK_USER_IDS, MOCK_VERSION, SEARCH_SEEDS, searchHit } from "./fixtures";
import { checkPassword } from "./policy";
import { banner, profileSettings } from "./profiles";
import { fail, ok } from "./reply";
import { paginate, route } from "./route";
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
  requireSession();
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
  return ok<SystemStatus>({
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
    warnings,
  });
});

// ---------------------------------------------------------------------------------
// Jobs and search

const JOB_STATES: readonly JobState[] = [
  "queued",
  "running",
  "waiting",
  "rolling_back",
  "succeeded",
  "failed",
  "rolled_back",
  "cancelled",
];

const STEPS = 10;

/** The document's JobSummary for a mock job. */
function jobSummary(j: MockJob): JobSummary {
  const done = j.state === "succeeded" ? STEPS : Math.round((j.progress ?? 0) * STEPS);
  return {
    id: j.id,
    kind: j.kind,
    state: j.state,
    title: j.title,
    created: { at: j.created_at, by: { kind: "user", id: MOCK_USER_IDS.alex, session: MOCK_USER_IDS.alex, strength: "passkey" } },
    cancel_requested: false,
    revision: db.revision,
    step_count: STEPS,
    steps_done: done,
    current_step: j.state === "running" || j.state === "waiting" ? Math.min(done, STEPS - 1) : null,
    targets: [],
  } as JobSummary;
}

const listJobs = route("get", "/api/v1/jobs", (ctx) => {
  requireSession();
  const filter = ctx.query("state");
  let states: JobState[] | null = null;
  if (filter !== null && filter.trim() !== "") {
    states = filter
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s !== "")
      .map((s) => {
        if (!(JOB_STATES as readonly string[]).includes(s)) {
          return fail("sys.invalid_query", { params: { name: "state", value: s } });
        }
        return s as JobState;
      });
  }
  const jobs = db.jobs
    .filter((j) => states === null || states.includes(j.state))
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .map(jobSummary);
  return ok(paginate(jobs, ctx.url, db.revision));
});

/** Case-insensitive; MAC fragments match with any separator (00-00-5e, 00:00:5e, 00005e). */
function matches(text: string, q: string): boolean {
  const t = text.toLowerCase();
  if (t.includes(q)) return true;
  const bare = (s: string) => s.replace(/[-:.]/g, "");
  return /^[0-9a-f:.-]+$/.test(q) && bare(q).length >= 4 && bare(t).includes(bare(q));
}

const search = route("get", "/api/v1/search", (ctx) => {
  requireSession();
  const q = (ctx.query("q") ?? "").trim().toLowerCase();
  const hits =
    q === ""
      ? []
      : SEARCH_SEEDS.filter((h) => matches(h.key, q) || matches(h.label, q)).map(searchHit);
  const limit = Number(ctx.query("limit") ?? "50");
  // The document lists search hits without paging: { items, revision }.
  return ok({ items: hits.slice(0, Number.isFinite(limit) && limit > 0 ? limit : 50), revision: db.revision });
});

export const systemRoutes: HttpHandler[] = [getSetup, completeSetup, health, ready, systemStatus, listJobs, search];
