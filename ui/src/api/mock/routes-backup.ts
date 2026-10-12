// Mock routes of the `backup` API area (OpenAPI tag `backup`). The package that adds the routes
// (WP3.4b) runs in parallel, so these answer the pending operations typed in
// settings/backup/model.ts, with the shapes of section 3 of the slice-3 plan: the status of the
// target directory with its backups and their manifests, "back up now" (an administrator with a
// sign-in within the last five minutes; a passphrase of at least 12 characters, or the recipient
// key file), and the schedule with the number of backups kept. A backup is written at once.
import type { HttpHandler } from "msw";
import type { BackupFile, BackupSettings, BackupStatus } from "../../settings/backup/model";
import { requireAdmin } from "./auth";
import { commit, db, onMockReset } from "./db";
import { looseRoute, pendingRoute } from "./pending-route";
import { ok, Problem, Reply } from "./reply";
import { DAY_MS, iso } from "./util";

/** How recent a sign-in must be for a backup. */
const FRESH_MS = 5 * 60 * 1000;
const STALE_MS = 7 * DAY_MS;

interface BackupState {
  backups: BackupFile[];
  settings: BackupSettings;
  recipient: boolean;
  lastAttempt: BackupStatus["last_attempt"];
  jobs: number;
}

function digest(seed: number): string {
  return Array.from({ length: 64 }, (_, i) => ((seed * 7 + i * 13) % 16).toString(16)).join("");
}

function backupFile(at: number, trigger: BackupFile["trigger"], key: BackupFile["key"]): BackupFile {
  const stamp = iso(at).replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  return {
    file: `tenko-${stamp}.tkbk`,
    created_at: iso(at),
    size_bytes: 4_812_345,
    tenko_version: "0.1.0",
    data_format: 3,
    revision: db.revision,
    audit_head: db.revision,
    ca_fingerprint: "SHA256:" + digest(at % 97).slice(0, 43),
    key,
    trigger,
    parts: [
      { name: "manifest", size_bytes: 1_024, sha256: digest(1) },
      { name: "store", size_bytes: 4_701_000, sha256: digest(2) },
      { name: "kek", size_bytes: 512, sha256: digest(3) },
      { name: "tls", size_bytes: 8_192, sha256: digest(4) },
      { name: "leases", size_bytes: 0, sha256: digest(5) },
    ],
  };
}

function fresh(): BackupState {
  const now = Date.now();
  return {
    backups: [backupFile(now - 3 * DAY_MS, "manual", "passphrase")],
    settings: { schedule: { kind: "off", time: "02:30", weekday: null }, keep: 7, revision: db.revision },
    recipient: false,
    lastAttempt: null,
    jobs: 0,
  };
}

/** The state of the mock; tests change it (a recipient, an old backup). */
export const backupState: BackupState = fresh();

onMockReset(() => {
  Object.assign(backupState, fresh());
});

function lastGood(): string | null {
  return backupState.backups.reduce<string | null>((max, b) => (max === null || b.created_at > max ? b.created_at : max), null);
}

export function backupStatus(): BackupStatus {
  const good = lastGood();
  const guarded = db.settings.profile === "standard" || db.settings.profile === "hardened";
  const { schedule } = backupState.settings;
  return {
    target: "/var/lib/tenko/backups",
    recipient: backupState.recipient,
    running: false,
    last_good_at: good,
    last_attempt: backupState.lastAttempt,
    stale: guarded && (good === null || Date.now() - Date.parse(good) > STALE_MS),
    next_at: schedule.kind === "off" ? null : iso(Date.now() + DAY_MS),
    backups: [...backupState.backups].sort((a, b) => b.created_at.localeCompare(a.created_at)),
  };
}

export const backupRoutes: HttpHandler[] = [
  looseRoute("get", "/api/v1/system/backups", () => {
    requireAdmin();
    return ok(backupStatus());
  }),

  looseRoute("post", "/api/v1/system/backups", async (ctx) => {
    const { session } = requireAdmin();
    if (Date.now() - session.created_at > FRESH_MS) {
      throw new Problem("auth.step_up_required", { params: { required: "fresh" } });
    }
    const body = await ctx.optionalBody();
    const passphrase = typeof body.passphrase === "string" ? body.passphrase : null;
    if (passphrase === null && !backupState.recipient) {
      throw new Problem("backup.key_required", { status: 422, detail: "a passphrase is needed: no recipient key file is configured" });
    }
    if (passphrase !== null && [...passphrase].length < 12) {
      throw new Problem("backup.passphrase_weak", { status: 422, detail: "the passphrase needs at least 12 characters" });
    }
    const now = Date.now();
    backupState.backups.push(backupFile(now, "manual", passphrase === null ? "recipient" : "passphrase"));
    backupState.backups = backupState.backups
      .sort((a, b) => b.created_at.localeCompare(a.created_at))
      .slice(0, backupState.settings.keep);
    backupState.lastAttempt = { at: iso(now), ok: true, error: null };
    backupState.jobs += 1;
    commit("system", { tables: ["backup.status"] });
    return new Reply(202, { job: `0190d1c2-0000-7000-8000-0000000d${String(backupState.jobs).padStart(4, "0")}` });
  }),

  pendingRoute("get", "/api/v1/settings/backup", () => {
    requireAdmin();
    return ok(backupState.settings);
  }),

  pendingRoute("put", "/api/v1/settings/backup", async (ctx) => {
    requireAdmin();
    const expected = ctx.ifMatch();
    if (expected !== null && expected !== "*" && expected !== backupState.settings.revision) {
      throw new Problem("sys.store.precondition_failed", { status: 412 });
    }
    const body = await ctx.body();
    const schedule = body.schedule as BackupSettings["schedule"] | undefined;
    const keep = body.keep;
    if (!schedule || !["off", "daily", "weekly"].includes(schedule.kind) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(schedule.time)) {
      throw new Problem("sys.invalid_request", { detail: "invalid schedule" });
    }
    if (typeof keep !== "number" || !Number.isInteger(keep) || keep < 1 || keep > 365) {
      throw new Problem("sys.invalid_request", { detail: "keep must be 1 to 365" });
    }
    commit("system", { tables: ["backup.settings"] });
    backupState.settings = { schedule: { ...schedule }, keep, revision: db.revision };
    return ok(backupState.settings);
  }),
];
