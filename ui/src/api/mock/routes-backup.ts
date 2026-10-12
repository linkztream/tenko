// Mock routes of the `backup` API area (OpenAPI tag `backup`; docs/backup.md): the status of the
// backups with the settings and their revision as `ETag`, "back up now" (an administrator with a
// sign-in within the last five minutes; a passphrase of at least 12 characters, or the
// configured recipient) and the interval schedule. A backup is written at once, as on the
// server. The error codes are those of section 11 of the document.
import type { components } from "../generated/schema";
import { requireAdmin } from "./auth";
import { commit, db, onMockReset } from "./db";
import { ok, Problem, Reply } from "./reply";
import { route } from "./route";
import { DAY_MS, HOUR_MS, iso } from "./util";

type S = components["schemas"];
type Run = S["BackupRunView"];
type Settings = S["BackupSettingsView"];

/** How recent a sign-in must be for a backup or a change of the settings. */
const FRESH_MS = 5 * 60 * 1000;
const STALE_MS = 7 * DAY_MS;
/** The newest backups the status lists. */
const RECENT = 20;
/** The records the server keeps. */
const KEPT_RECORDS = 100;
const DEFAULT_DIR = "/var/lib/tenko/backups";
const MIN_PASSPHRASE = 12;

interface BackupState {
  runs: Run[];
  settings: Settings;
  restored: S["RestoreNoticeView"] | null;
  running: boolean;
  counter: number;
}

function fileName(at: number): string {
  const stamp = iso(at).replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  return `tenko-backup-${stamp}-n1.tkbk`;
}

function run(at: number, reason: Run["reason"], slots: string[], id: number): Run {
  return {
    id: `0190d1c2-0000-7000-8000-${String(id).padStart(12, "0")}`,
    by: reason === "scheduled" ? "system" : "user:0190d1c2-0000-7000-8000-000000000001",
    bytes: 4_812_345,
    file: fileName(at),
    finished_at: iso(at),
    job: null,
    node: 1,
    outcome: "succeeded",
    reason,
    revision: db.revision,
    slots,
    started_at: iso(at - 2_000),
    target_dir: DEFAULT_DIR,
  };
}

function fresh(): BackupState {
  return {
    runs: [run(Date.now() - 3 * DAY_MS, "manual", ["passphrase"], 1)],
    settings: {
      effective_target_dir: DEFAULT_DIR,
      enabled: false,
      include_config: true,
      interval_hours: 24,
      keep: 7,
      recipient: null,
      revision: db.revision,
      target_dir: null,
    },
    restored: null,
    running: false,
    counter: 1,
  };
}

/** The state of the mock; tests change it (a recipient, an old backup, a failed run). */
export const backupState: BackupState = fresh();

onMockReset(() => {
  Object.assign(backupState, fresh());
});

function newestFirst(runs: readonly Run[]): Run[] {
  return [...runs].sort((a, b) => b.finished_at.localeCompare(a.finished_at));
}

/** The status `GET /system/backups` answers. */
export function backupStatus(): S["BackupStatusView"] {
  const recent = newestFirst(backupState.runs);
  const lastGood = recent.find((r) => r.outcome === "succeeded") ?? null;
  const newest = recent[0] ?? null;
  const lastFailed = newest && newest.outcome === "failed" ? newest : null;
  const { settings } = backupState;
  const now = Date.now();
  const strict = db.settings.profile === "standard" || db.settings.profile === "hardened";
  const warnings: S["StatusWarning"][] = [];
  if (strict && (lastGood === null || now - Date.parse(lastGood.finished_at) > STALE_MS)) {
    warnings.push({
      code: "backup.stale",
      detail: lastGood ? "the last good backup is more than 7 days old" : "there has been no backup since setup, more than 7 days ago",
      params: { days: "7" },
    });
  }
  if (lastFailed) {
    warnings.push({
      code: "backup.failed",
      detail: `the last backup failed: ${lastFailed.error?.detail ?? "unknown cause"}`,
      params: { at: lastFailed.finished_at, error: lastFailed.error?.code ?? "" },
    });
  }
  if (backupState.restored && (lastGood === null || Date.parse(lastGood.finished_at) <= Date.parse(backupState.restored.restored_at))) {
    warnings.push({ code: "backup.restored", detail: "the installation was started from a restore; take a backup", params: {} });
  }
  const lastScheduled = recent.find((r) => r.outcome === "succeeded" && r.reason === "scheduled");
  return {
    age_seconds: lastGood ? Math.max(0, Math.floor((now - Date.parse(lastGood.finished_at)) / 1000)) : null,
    last_failed: lastFailed,
    last_good: lastGood,
    next_due_at: settings.enabled ? iso(lastScheduled ? Date.parse(lastScheduled.finished_at) + settings.interval_hours * HOUR_MS : now) : null,
    recent: recent.slice(0, RECENT),
    restored: backupState.restored,
    running: backupState.running,
    settings: { ...settings },
    warnings,
  };
}

/** Both writes need an administrator who signed in within the last five minutes. */
function requireFresh() {
  const principal = requireAdmin();
  if (Date.now() - principal.session.created_at > FRESH_MS) {
    throw new Problem("auth.step_up_required", { params: { required: "fresh" } });
  }
  return principal;
}

const RECIPIENT = /^tkbr1:[A-Za-z0-9_-]{43}$/;

function etag(revision: number | null | undefined): Record<string, string> {
  return revision === null || revision === undefined ? {} : { ETag: `"${revision}"` };
}

function invalidRequest(field: string, what: string): never {
  throw new Problem("sys.invalid_request", { detail: `${field} must be ${what}` });
}

function boolField(body: Record<string, unknown>, key: string): boolean {
  const value = body[key];
  if (typeof value !== "boolean") return invalidRequest(key, "true or false");
  return value;
}

function intField(body: Record<string, unknown>, key: string): number {
  const value = body[key];
  if (typeof value !== "number" || !Number.isInteger(value)) return invalidRequest(key, "a whole number");
  return value;
}

function optText(body: Record<string, unknown>, key: string): string | null {
  const value = body[key];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") return invalidRequest(key, "a text");
  return value;
}

export const backupRoutes = [
  route("get", "/api/v1/system/backups", () => {
    requireAdmin();
    const status = backupStatus();
    return ok(status, etag(status.settings.revision));
  }),

  route("post", "/api/v1/system/backups", async (ctx) => {
    const { user } = requireFresh();
    const body = await ctx.optionalBody();
    const passphrase = optText(body, "passphrase");
    if (backupState.running) throw new Problem("backup.running", { status: 409, detail: "a backup is running on this controller" });
    if (passphrase === null && !backupState.settings.recipient) {
      throw new Problem("backup.key.missing", { status: 422, detail: "no recipient is configured and no passphrase was given" });
    }
    if (passphrase !== null && [...passphrase].length < MIN_PASSPHRASE) {
      throw new Problem("backup.passphrase.weak", {
        status: 422,
        detail: "the passphrase needs at least 12 characters",
        params: { min: String(MIN_PASSPHRASE) },
      });
    }
    const slots = [...(backupState.settings.recipient ? ["recipient"] : []), ...(passphrase === null ? [] : ["passphrase"])];
    backupState.counter += 1;
    const written = run(Date.now(), "manual", slots, backupState.counter);
    written.by = `user:${user.id}`;
    backupState.runs = newestFirst([written, ...backupState.runs]).slice(0, KEPT_RECORDS);
    commit("system", { tables: ["backup.runs"] });
    return new Reply(201, written);
  }),

  route("put", "/api/v1/system/backups/settings", async (ctx) => {
    requireFresh();
    const expected = ctx.ifMatch();
    const body = await ctx.body();
    if (expected !== null && expected !== "*" && expected !== backupState.settings.revision) {
      throw new Problem("sys.store.precondition_failed", { status: 409 });
    }
    const enabled = boolField(body, "enabled");
    const includeConfig = boolField(body, "include_config");
    const interval = intField(body, "interval_hours");
    const keep = intField(body, "keep");
    const recipient = optText(body, "recipient");
    const targetDir = optText(body, "target_dir");
    if (interval < 1 || interval > 168) {
      throw new Problem("backup.settings.invalid", { status: 422, detail: "interval_hours must be 1 to 168", params: { field: "interval_hours" } });
    }
    if (keep < 1 || keep > 365) {
      throw new Problem("backup.settings.invalid", { status: 422, detail: "keep must be 1 to 365", params: { field: "keep" } });
    }
    if (targetDir !== null && !targetDir.startsWith("/") && !/^[A-Za-z]:[\\/]/.test(targetDir)) {
      throw new Problem("backup.settings.invalid", { status: 422, detail: "target_dir must be an absolute directory", params: { field: "target_dir" } });
    }
    if (recipient !== null && !RECIPIENT.test(recipient.trim())) {
      throw new Problem("backup.key.invalid", { status: 422, detail: "a recipient is tkbr1: followed by 43 base64url characters" });
    }
    if (enabled && recipient === null) {
      throw new Problem("backup.key.missing", { status: 422, detail: "scheduled backups need a recipient" });
    }
    commit("system", { tables: ["backup.settings"] });
    const trimmed = recipient === null ? null : recipient.trim();
    backupState.settings = {
      effective_target_dir: targetDir ?? DEFAULT_DIR,
      enabled,
      include_config: includeConfig,
      interval_hours: interval,
      keep,
      recipient: trimmed,
      revision: db.revision,
      target_dir: targetDir,
    };
    return ok({ ...backupState.settings }, etag(db.revision));
  }),
];
