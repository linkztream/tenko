// Updates and modules (OPS-24, OPS-25, TGL-23) for the mock API: the update status with two
// newer releases, the check, the release list upload, the install and the file upload (a job
// that finishes at once, then a "restart" after which the health probe names the new version),
// the what-is-new notes, the module switch, and the toggle TGL-23 in the security settings.
//
// The state lives in `mockUpdates`; tests (and a developer in the browser) change it to play
// other situations: a container, an air-gapped installation, a step-up answer, a failing check.
//
// The backup before an install follows the server's rule (ADR 0023) over the backups of
// `routes-backup.ts`: without `backup` an install needs a good backup younger than an hour
// (409 `update.backup_required`), `run` writes one as the job's first step, and `skip` is
// refused under the Hardened profile.
//
// What the mock simplifies: the install job has four automatic steps and is done the moment it
// starts (the mock job engine finishes automatic steps at once), and the "restart" is a delay
// after which `GET /health` answers with the new version.
import { http, type HttpHandler } from "msw";
import type { components } from "../generated/schema";
import type { SecuritySettings, SecuritySettingsView, ToggleState } from "../types";
import { currentPrincipal, requireAdmin, requireSession } from "./auth";
import { db, onMockReset, recordEvent } from "./db";
import { MOCK_VERSION } from "./fixtures";
import { createJob } from "./job-store";
import { Problem, Reply, noContent, ok } from "./reply";
import { route } from "./route";
import { adminRoutes } from "./routes-admin";
import { backupState, newestGoodAge, writeBackup } from "./routes-backup";
import { iso } from "./util";
import { isRecord } from "./validate";

type S = components["schemas"];
type Release = S["Release"];
type InstallBlock = S["InstallBlock"];
type UpdateStatus = S["UpdateStatus"];
type UpdateAttempt = S["UpdateAttempt"];
type UpdatePolicy = S["UpdatePolicy"];
type ModuleName = S["ModuleSet"][number];

// ---------------------------------------------------------------------------------
// Versions and releases

export const MODULE_ORDER: readonly ModuleName[] = ["ipam", "dns", "dhcp", "discovery"];

/** The platform of the mock server. */
export const MOCK_PLATFORM = "linux-x86_64";

/** The text a release file of the mock holds; its SHA-256 is in the manifest. */
export function mockReleaseFile(version: string): string {
  return `tenko-release-${version}`;
}

const SHA256: Record<string, string> = {
  "0.1.1": "49f434cb065c412c54bcb91f4860c1e922c3b0d8e87c92a14a7bde48cbac0848",
  "0.2.0": "541dada4a75ff47e524dafb9d9246b273675ef5c908a822edbd5b9929b3aa0a7",
};

function asset(version: string): NonNullable<Release["assets"]>[number] {
  return {
    name: `tenko-${version}-${MOCK_PLATFORM}`,
    platform: MOCK_PLATFORM,
    sha256: SHA256[version] ?? "0".repeat(64),
    size: mockReleaseFile(version).length,
    url: `https://releases.example.org/tenko/${version}/tenko-${version}-${MOCK_PLATFORM}`,
  };
}

/** The releases the mock knows: two newer than the running version, and the running one. */
export function seedReleases(): Release[] {
  return [
    {
      version: "0.2.0",
      date: "2026-11-12",
      notes: [
        "### Added",
        "- Modules: an installation can run only the parts it needs.",
        "- *Release notes* in the web interface, with a **what is new** dialog after an upgrade.",
        "",
        "### Changed",
        "- The data format is now 2. The first start converts the store.",
      ].join("\n"),
      requires_action: true,
      action: [
        "Do this before you upgrade:",
        "",
        "- Make a backup of the data directory.",
        "- Check that a service manager restarts `tenko`.",
      ].join("\n"),
      format: 2,
      assets: [asset("0.2.0")],
      image: "registry.example.org/tenko:0.2.0",
    },
    {
      version: "0.1.1",
      date: "2026-10-30",
      notes: [
        "### Security",
        "- Closes a session fixation problem in the sign-in flow. See [the advisory](https://example.org/tenko/advisories/1).",
        "",
        "### Fixed",
        "- The audit log no longer shows a record twice after a restart.",
      ].join("\n"),
      security: true,
      format: 1,
      assets: [asset("0.1.1")],
      image: "registry.example.org/tenko:0.1.1",
    },
    {
      version: MOCK_VERSION,
      date: "2026-10-01",
      notes: ["### Added", "- Notes of the running version, shown after an upgrade."].join("\n"),
      format: 1,
    },
  ];
}

interface Parsed {
  core: number[];
  pre: string | null;
}

function parseVersion(text: string): Parsed | null {
  const match = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(text);
  if (!match) return null;
  return { core: [Number(match[1]), Number(match[2]), Number(match[3])], pre: match[4] ?? null };
}

/** SemVer order, simplified: the numbers first, then a pre-release below its release. */
export function compareVersions(a: string, b: string): number {
  const x = parseVersion(a);
  const y = parseVersion(b);
  if (!x || !y) return a < b ? -1 : a > b ? 1 : 0;
  for (let i = 0; i < 3; i += 1) {
    const d = (x.core[i] ?? 0) - (y.core[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  if (x.pre === y.pre) return 0;
  if (x.pre === null) return 1;
  if (y.pre === null) return -1;
  return x.pre < y.pre ? -1 : 1;
}

// ---------------------------------------------------------------------------------
// The state

export interface MockUpdates {
  running: string;
  /** Every release the mock knows, newest first. */
  releases: Release[];
  manifest: { origin: "fetched" | "uploaded"; at: string; releases: number } | null;
  lastChecked: string | null;
  lastError: string | null;
  /** The release source cannot be reached (the next check fails with `update.fetch_failed`). */
  fetchFails: boolean;
  /** The address of the release manifest (`check.source`). */
  source: string;
  /** `tenko.toml` says `air_gapped`: no check, no download. */
  airGapped: boolean;
  /** Why this installation cannot install by itself (a container, a cluster, ...), or null. */
  blocked: InstallBlock | null;
  /** The session that has to sign in again before an install is accepted (step-up), or null. */
  stepUpSession: string | null;
  attempt: UpdateAttempt | null;
  /** After an install: the version that answers `GET /health` from `readyAt`. */
  restart: { version: string; readyAt: number; rollBack: boolean } | null;
  /** How long the "restart" takes. */
  restartMs: number;
  /** The next restart fails: the previous version runs again. */
  rollBackNext: boolean;
  /** `GET /system/updates` answers 503: the server has no update service. */
  unavailable: boolean;
  /** What the signed-in user last saw of the release notes; null for a new user. */
  lastSeen: string | null;
  /** How many times `whats-new/seen` was posted. */
  seenPosts: number;
  modules: { running: ModuleName[]; configured: ModuleName[]; pinned: boolean; unavailable: boolean };
  /** How many times `PUT /system/modules` was called. */
  modulesPuts: number;
  /** What the last started install did about the backup before it: `recent`, `run` or `skipped`. */
  lastBackupPlan: "recent" | "run" | "skipped" | null;
}

function fresh(): MockUpdates {
  return {
    running: MOCK_VERSION,
    releases: seedReleases(),
    manifest: { origin: "fetched", at: iso(Date.now() - 3_600_000), releases: 3 },
    lastChecked: iso(Date.now() - 3_600_000),
    lastError: null,
    source: "https://github.example.org/example/tenko/releases/latest/download/releases.json",
    fetchFails: false,
    airGapped: false,
    blocked: null,
    stepUpSession: null,
    attempt: null,
    restart: null,
    restartMs: 3000,
    rollBackNext: false,
    unavailable: false,
    lastSeen: "0.0.9",
    seenPosts: 0,
    modules: { running: [...MODULE_ORDER], configured: [...MODULE_ORDER], pinned: false, unavailable: false },
    modulesPuts: 0,
    lastBackupPlan: null,
  };
}

/** The state of the updates mock. One object; `resetUpdatesMock` replaces its members. */
export const mockUpdates: MockUpdates = fresh();

export function resetUpdatesMock(): void {
  Object.assign(mockUpdates, fresh());
}

onMockReset(() => resetUpdatesMock());

// ---------------------------------------------------------------------------------
// TGL-23

const UPDATES_DEFAULT: Readonly<Record<SecuritySettings["profile"], UpdatePolicy>> = {
  home: { check: true, install: "ui" },
  standard: { check: true, install: "ui_step_up" },
  hardened: { check: true, install: "upload_only" },
  lab: { check: true, install: "ui" },
};

/** TGL-23 of a settings object: its own value, or the default of its profile. */
export function updatesPolicy(settings: SecuritySettings = db.settings): UpdatePolicy {
  return settings.updates ?? UPDATES_DEFAULT[settings.profile];
}

function updatesToggle(settings: SecuritySettings): ToggleState {
  const value = updatesPolicy(settings);
  const fallback = UPDATES_DEFAULT[settings.profile];
  return {
    id: "TGL-23",
    setting: "updates",
    value: { ...value },
    profile_default: { ...fallback },
    deviates: value.check !== fallback.check || value.install !== fallback.install,
    weaker_than_home: !value.check,
  };
}

function parseUpdatesPolicy(value: unknown): UpdatePolicy {
  if (!isRecord(value) || typeof value.check !== "boolean") {
    throw new Problem("sys.invalid_value", { status: 400, params: { name: "updates" } });
  }
  const install = value.install;
  if (install !== "ui" && install !== "ui_step_up" && install !== "upload_only") {
    throw new Problem("sys.invalid_value", { status: 400, params: { name: "updates.install" } });
  }
  return { check: value.check, install };
}

/** The security view of the settings mock, with TGL-23 added when the settings mock lacks it. */
function withUpdatesToggle(view: SecuritySettingsView): SecuritySettingsView {
  if (view.toggles.some((t) => t.id === "TGL-23")) return view;
  const toggle = updatesToggle(db.settings);
  const banner = { ...view.banner, deviations: [...view.banner.deviations] };
  if (toggle.weaker_than_home) banner.weaker_than_home = true;
  if (toggle.deviates) banner.deviations.push("TGL-23");
  // `settings.updates` is there once someone set it; until then the toggle carries the default.
  return { ...view, toggles: [...view.toggles, toggle], banner };
}

const SETTINGS_PATH = "/api/v1/settings/security";

/** The handler of the settings mock for a method, to decorate. */
function settingsHandler(method: "GET" | "PATCH"): HttpHandler | undefined {
  return adminRoutes.find((h) => {
    const info = (h as unknown as { info: { method: string; path: string } }).info;
    return info.method === method && info.path === SETTINGS_PATH;
  });
}

async function viewResponse(original: Response): Promise<Response> {
  if (!original.ok) return original;
  const view = withUpdatesToggle((await original.clone().json()) as SecuritySettingsView);
  const headers = new Headers(original.headers);
  headers.delete("content-length");
  return new Response(JSON.stringify(view), { status: original.status, headers });
}

const getSecurity = http.get(SETTINGS_PATH, async ({ request, requestId }) => {
  const result = await settingsHandler("GET")?.run({ request, requestId });
  return result?.response ? viewResponse(result.response) : undefined;
});

const patchSecurity = http.patch(SETTINGS_PATH, async ({ request, requestId }) => {
  let next: UpdatePolicy | undefined;
  try {
    const body: unknown = await request.clone().json();
    if (isRecord(body) && body.updates !== undefined && body.updates !== null) next = parseUpdatesPolicy(body.updates);
  } catch (error) {
    if (error instanceof Problem) return error.reply.toResponse();
  }
  const result = await settingsHandler("PATCH")?.run({ request, requestId });
  if (!result?.response) return undefined;
  const response = result.response;
  if (!response.ok) return response;
  // The settings mock committed the other members; the updates policy goes on top of its answer.
  const view = (await response.clone().json()) as SecuritySettingsView;
  if (next) {
    db.settings.updates = next;
    view.settings = { ...view.settings, updates: next };
  }
  const headers = new Headers(response.headers);
  headers.delete("content-length");
  return new Response(JSON.stringify(withUpdatesToggle(view)), { status: response.status, headers });
});

// ---------------------------------------------------------------------------------
// The status

/** A pending restart that has had its time: the new version answers (or the old one is back). */
function settleRestart(): void {
  const restart = mockUpdates.restart;
  if (!restart || Date.now() < restart.readyAt) return;
  const attempt = mockUpdates.attempt;
  if (restart.rollBack) {
    if (attempt) mockUpdates.attempt = { ...attempt, state: "rolled_back", at: iso(Date.now()), reason: "upgrade.not_ready" };
  } else {
    mockUpdates.running = restart.version;
    if (attempt) mockUpdates.attempt = { ...attempt, state: "confirmed", at: iso(Date.now()) };
  }
  mockUpdates.restart = null;
}

function newer(): Release[] {
  return mockUpdates.releases.filter((r) => compareVersions(r.version, mockUpdates.running) > 0);
}

function checkOffReason(): "air_gapped" | "setting" | null {
  if (mockUpdates.airGapped) return "air_gapped";
  return updatesPolicy().check ? null : "setting";
}

function installing(): boolean {
  return mockUpdates.attempt?.state === "installing" || mockUpdates.attempt?.state === "restarting";
}

/** Why the server cannot fetch and switch by itself now, or null when it can. */
function blockOf(forUpload: boolean): InstallBlock | null {
  if (newer().length === 0) return "up_to_date";
  if (installing()) return "in_progress";
  if (mockUpdates.blocked) return mockUpdates.blocked;
  if (!forUpload) {
    if (mockUpdates.airGapped) return "air_gapped";
    if (updatesPolicy().install === "upload_only") return "upload_only";
  }
  return null;
}

export function updateStatus(): UpdateStatus {
  settleRestart();
  const releases = newer();
  const policy = updatesPolicy();
  const source = blockOf(false);
  const upload = blockOf(true);
  const reason = checkOffReason();
  const latest = releases[0]?.version ?? null;
  const status: UpdateStatus = {
    running: mockUpdates.running,
    format: 1,
    platform: MOCK_PLATFORM,
    update_available: releases.length > 0,
    security: releases.some((r) => r.security),
    requires_action: releases.some((r) => r.requires_action),
    releases: structuredClone(releases),
    check: {
      enabled: reason === null,
      interval_hours: 24,
      source: mockUpdates.source,
    },
    install: {
      policy: policy.install,
      step_up: policy.install === "ui_step_up",
      from_source: source === null,
      upload: upload === null,
      ready_timeout_secs: 120,
      backup: backupGate(),
    },
  };
  if (latest) status.latest = latest;
  if (reason) status.check.off_reason = reason;
  if (mockUpdates.lastChecked) status.check.last_checked = mockUpdates.lastChecked;
  if (mockUpdates.lastError) status.check.last_error = mockUpdates.lastError;
  if (mockUpdates.manifest) status.manifest = { ...mockUpdates.manifest };
  if (source) status.install.from_source_blocked = source;
  if (upload) status.install.upload_blocked = upload;
  if (mockUpdates.blocked === "container" && latest) status.install.pull_command = `docker pull registry.example.org/tenko:${latest}`;
  if (mockUpdates.attempt) status.attempt = { ...mockUpdates.attempt };
  return status;
}

function requireService(): void {
  if (mockUpdates.unavailable) {
    throw new Problem("update.unavailable", { status: 503, detail: "the server provides no update service" });
  }
}

const getUpdates = route("get", "/api/v1/system/updates", () => {
  requireAdmin();
  requireService();
  return ok(updateStatus());
});

const checkUpdates = route("post", "/api/v1/system/updates/check", () => {
  requireAdmin();
  requireService();
  const reason = checkOffReason();
  if (reason) throw new Problem("update.check_off", { status: 409, params: { reason } });
  if (mockUpdates.fetchFails) {
    mockUpdates.lastError = "update.fetch_failed";
    recordEvent("admin", { tables: ["sys.updates"] });
    throw new Problem("update.fetch_failed", { status: 502, detail: "the release source did not answer" });
  }
  mockUpdates.lastError = null;
  mockUpdates.lastChecked = iso(Date.now());
  mockUpdates.manifest = { origin: "fetched", at: iso(Date.now()), releases: mockUpdates.releases.length };
  recordEvent("admin", { tables: ["sys.updates"] });
  return ok(updateStatus());
});

/** The releases of an uploaded release list; a list that is not one fails like the server's. */
function parseManifest(body: unknown): Release[] {
  if (!isRecord(body) || !Array.isArray(body.releases)) {
    throw new Problem("update.manifest.schema", { status: 400, detail: "the release list has no releases" });
  }
  return body.releases.map((entry): Release => {
    if (!isRecord(entry) || typeof entry.version !== "string" || parseVersion(entry.version) === null) {
      throw new Problem("update.manifest.invalid", { status: 400, detail: "a release has no valid version" });
    }
    if (typeof entry.date !== "string" || typeof entry.notes !== "string") {
      throw new Problem("update.manifest.invalid", { status: 400, detail: "a release has no date or notes" });
    }
    return entry as unknown as Release;
  });
}

const putManifest = http.put("/api/v1/system/updates/manifest", async ({ request }) => {
  try {
    requireAdmin();
    requireService();
    let body: unknown;
    try {
      body = JSON.parse(await request.text());
    } catch {
      throw new Problem("update.manifest.json", { status: 400, detail: "the release list is not JSON" });
    }
    const incoming = parseManifest(body);
    const known = new Map(mockUpdates.releases.map((r) => [r.version, r]));
    for (const release of incoming) known.set(release.version, release);
    mockUpdates.releases = [...known.values()].sort((a, b) => compareVersions(b.version, a.version));
    mockUpdates.manifest = { origin: "uploaded", at: iso(Date.now()), releases: incoming.length };
    recordEvent("admin", { tables: ["sys.updates"] });
    return ok(updateStatus()).toResponse();
  } catch (error) {
    if (error instanceof Problem) return error.reply.toResponse();
    throw error;
  }
});

// ---------------------------------------------------------------------------------
// Install and upload

const STEPS = ["sys.update.fetch", "sys.update.verify", "sys.update.check", "sys.update.switch"] as const;

/** The server's limit: a good backup younger than this is the restore point of an install. */
export const BACKUP_MAX_AGE_SECONDS = 3_600;

/** The backup part of the status: the newest good backup's age and what a request must say. */
function backupGate(): S["PreUpdateBackupStatus"] {
  const age = newestGoodAge();
  return {
    ...(age === null ? {} : { age_seconds: age }),
    max_age_seconds: BACKUP_MAX_AGE_SECONDS,
    skip_allowed: db.settings.profile !== "hardened",
    recipient: backupState.settings.recipient !== null && backupState.settings.recipient !== undefined,
  };
}

type BackupAnswer = "run" | "skip" | null;

function backupAnswer(value: unknown): BackupAnswer {
  if (value === undefined || value === null) return null;
  if (value === "run" || value === "skip") return value;
  throw new Problem("sys.invalid_value", { status: 400, params: { name: "backup" } });
}

/** The server's rule of the backup before an install (ADR 0023). */
function backupPlan(answer: BackupAnswer): "recent" | "run" | "skipped" {
  const gate = backupGate();
  const required = (skipRefused: boolean) => {
    const params: Record<string, string> = { max_age_seconds: String(gate.max_age_seconds) };
    if (gate.age_seconds !== undefined && gate.age_seconds !== null) params.age_seconds = String(gate.age_seconds);
    if (skipRefused) params.skip_allowed = "false";
    return new Problem("update.backup_required", { status: 409, params, detail: "a backup is needed before this install" });
  };
  if (answer === "run") {
    if (!gate.recipient) throw new Problem("backup.key.missing", { status: 422, detail: "no recipient is configured" });
    return "run";
  }
  if (answer === "skip") {
    if (!gate.skip_allowed) throw required(true);
    return "skipped";
  }
  if (gate.age_seconds !== undefined && gate.age_seconds !== null && gate.age_seconds < gate.max_age_seconds) return "recent";
  throw required(false);
}

/** The step-up rule of TGL-23: a session that has to sign in again is refused until it does. */
function requireFreshSignIn(): void {
  const session = currentPrincipal()?.session.id ?? null;
  if (mockUpdates.stepUpSession !== null && mockUpdates.stepUpSession === session) {
    throw new Problem("auth.step_up_required", { status: 403, detail: "sign in again with a stronger method" });
  }
}

function startInstall(version: string, plan: "recent" | "run" | "skipped"): Reply<{ job_id: string; version: string }> {
  const steps: string[] = [...STEPS];
  if (plan === "run") {
    // The job's first step: the backup, recorded with the reason `before_update`. A failure
    // fails the install before anything changed.
    steps.unshift("sys.update.backup");
    writeBackup(`user:${currentPrincipal()?.user.id ?? ""}`, null, version);
  }
  mockUpdates.lastBackupPlan = plan;
  const jobId = createJob({
    kind: "sys.update",
    title: "jobs.title.update_install",
    targets: [],
    timeoutSecs: 900,
    steps: steps.map((kind) => ({ kind, automatic: true })),
    preview: false,
  });
  const now = Date.now();
  mockUpdates.attempt = { from: mockUpdates.running, to: version, state: "restarting", at: iso(now), job_id: jobId };
  mockUpdates.restart = { version, readyAt: now + mockUpdates.restartMs, rollBack: mockUpdates.rollBackNext };
  mockUpdates.rollBackNext = false;
  recordEvent("admin", { tables: ["sys.updates"] });
  return new Reply(202, { job_id: jobId, version });
}

function knownRelease(version: string): Release {
  const release = mockUpdates.releases.find((r) => r.version === version);
  if (!release) throw new Problem("update.version_unknown", { status: 400, params: { version } });
  if (compareVersions(version, mockUpdates.running) <= 0) {
    throw new Problem("update.not_newer", { status: 400, params: { version } });
  }
  return release;
}

const installUpdate = route("post", "/api/v1/system/updates/install", async (ctx) => {
  requireAdmin();
  requireService();
  const body = await ctx.body();
  const version = typeof body.version === "string" ? body.version : "";
  knownRelease(version);
  const blocked = blockOf(false);
  if (blocked) throw new Problem("update.install_blocked", { status: 409, params: { reason: blocked } });
  requireFreshSignIn();
  const plan = backupPlan(backupAnswer(body.backup));
  return startInstall(version, plan);
});

async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

const uploadUpdate = route("post", "/api/v1/system/updates/upload", async (ctx) => {
  requireAdmin();
  requireService();
  const version = ctx.query("version") ?? "";
  const release = knownRelease(version);
  const blocked = blockOf(true);
  if (blocked) throw new Problem("update.install_blocked", { status: 409, params: { reason: blocked } });
  requireFreshSignIn();
  const expected = release.assets?.find((a) => a.platform === MOCK_PLATFORM);
  if (!expected) throw new Problem("update.install_blocked", { status: 409, params: { reason: "no_asset" } });
  // Answered before the body is read, as on the server.
  const plan = backupPlan(backupAnswer(ctx.query("backup")));
  const bytes = await ctx.request.arrayBuffer();
  if (bytes.byteLength > expected.size) throw new Problem("update.size_mismatch", { status: 413 });
  if (bytes.byteLength !== expected.size) throw new Problem("update.size_mismatch", { status: 400 });
  if ((await sha256Hex(bytes)) !== expected.sha256) throw new Problem("update.checksum_mismatch", { status: 400 });
  return startInstall(version, plan);
});

// ---------------------------------------------------------------------------------
// What is new

const getWhatsNew = route("get", "/api/v1/system/updates/whats-new", () => {
  requireSession();
  requireService();
  settleRestart();
  const last = mockUpdates.lastSeen;
  const releases = last === null ? [] : mockUpdates.releases.filter((r) => compareVersions(r.version, last) > 0 && compareVersions(r.version, mockUpdates.running) <= 0);
  return ok({
    running: mockUpdates.running,
    ...(last === null ? {} : { last_seen: last }),
    show: last !== null && last !== mockUpdates.running && releases.length > 0,
    releases: structuredClone(releases),
  });
});

const markWhatsNewSeen = route("post", "/api/v1/system/updates/whats-new/seen", () => {
  requireSession();
  requireService();
  mockUpdates.lastSeen = mockUpdates.running;
  mockUpdates.seenPosts += 1;
  return noContent();
});

// ---------------------------------------------------------------------------------
// Modules

function moduleView(): S["ModuleSettings"] {
  const { running, configured, pinned } = mockUpdates.modules;
  const same = running.length === configured.length && running.every((m, i) => m === configured[i]);
  return { running: [...running], configured: [...configured], pinned, restart: same ? "none" : "required" };
}

function requireModuleService(): void {
  if (mockUpdates.modules.unavailable) throw new Problem("modules.unavailable", { status: 503 });
}

const getModules = route("get", "/api/v1/system/modules", () => {
  requireSession();
  requireModuleService();
  return ok(moduleView());
});

const putModules = route("put", "/api/v1/system/modules", async (ctx) => {
  requireAdmin();
  requireModuleService();
  mockUpdates.modulesPuts += 1;
  const body = await ctx.body();
  const list = body.modules;
  if (!Array.isArray(list) || list.length === 0 || !list.every((m) => MODULE_ORDER.includes(m as ModuleName))) {
    throw new Problem("sys.invalid_value", { status: 400, params: { name: "modules" } });
  }
  if (mockUpdates.modules.pinned) {
    throw new Problem("modules.pinned", { status: 409, detail: "tenko.toml sets the modules" });
  }
  const chosen = MODULE_ORDER.filter((m) => list.includes(m));
  mockUpdates.modules.configured = chosen;
  recordEvent("admin", { tables: ["sys.modules"] });
  return ok(moduleView());
});

/** The modules `GET /system/status` carries (administrators only). */
export function statusModules(): ModuleName[] {
  return [...mockUpdates.modules.running];
}

/** The status warning while a module change waits for a restart. */
export function modulesWarnings(): { code: string; detail: string; params: Record<string, string> }[] {
  const view = moduleView();
  if (view.restart === "none") return [];
  return [
    {
      code: "sys.modules.restart_required",
      detail: "the modules changed; restart the server to apply the change",
      params: { configured: view.configured.join(","), running: view.running.join(",") },
    },
  ];
}

// ---------------------------------------------------------------------------------
// Health: after an install the new version answers once the "restart" is over

const health = route("get", "/api/v1/health", () => {
  settleRestart();
  if (mockUpdates.restart && Date.now() < mockUpdates.restart.readyAt) {
    // The server is down while it restarts.
    throw new Problem("sys.unavailable", { status: 503, detail: "the server is restarting" });
  }
  return ok({ status: "ok", version: mockUpdates.running });
});

export const updatesRoutes: HttpHandler[] = [
  getUpdates,
  checkUpdates,
  putManifest,
  installUpdate,
  uploadUpdate,
  getWhatsNew,
  markWhatsNewSeen,
  getModules,
  putModules,
  health,
  getSecurity,
  patchSecurity,
];
