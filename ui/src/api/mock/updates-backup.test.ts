// The rule of the backup before an install in the mock (ADR 0023), through `fetch`: without an
// answer an install needs a good backup younger than an hour (409 `update.backup_required`),
// `run` writes one (needs a recipient) and `skip` is refused under the Hardened profile.
import { beforeEach, describe, expect, it } from "vitest";
import { backupState } from "./routes-backup";
import { db, resetMockDb } from "./db";
import { mockUpdates } from "./routes-updates";
import { iso } from "./util";

const RECIPIENT = `tkbr1:${"B".repeat(43)}`;
const HOUR = 3_600_000;

interface Answer<T> {
  status: number;
  body: T;
}

async function post<T = unknown>(path: string, json: unknown, key = "mock-test-key"): Promise<Answer<T>> {
  const res = await fetch(path, {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json", "idempotency-key": key },
    body: JSON.stringify(json),
  });
  const text = await res.text();
  return { status: res.status, body: (text ? JSON.parse(text) : undefined) as T };
}

async function get<T = unknown>(path: string): Promise<Answer<T>> {
  const res = await fetch(path, { headers: { accept: "application/json" } });
  return { status: res.status, body: (await res.json()) as T };
}

interface Problem {
  code: string;
  params: Record<string, string>;
}

const install = (extra: object = {}) => post<Problem & { job_id?: string; version?: string }>("/api/v1/system/updates/install", { version: "0.2.0", ...extra });

/** The newest backup finished `ms` ago. */
function backedUp(ms: number) {
  backupState.runs = backupState.runs.map((r) => ({ ...r, finished_at: iso(Date.now() - ms) }));
}

beforeEach(() => {
  resetMockDb("signed-in");
});

describe("the update status", () => {
  it("reports the newest good backup, the limit, whether a skip is allowed and whether there is a recipient", async () => {
    const age = (await get<{ install: { backup: Record<string, unknown> } }>("/api/v1/system/updates")).body.install.backup;
    expect(age.max_age_seconds).toBe(3600);
    expect(age.skip_allowed).toBe(true);
    expect(age.recipient).toBe(false);
    expect(age.age_seconds).toBeGreaterThanOrEqual(3 * 86_400);

    backupState.settings.recipient = RECIPIENT;
    db.settings.profile = "hardened";
    backupState.runs = [];
    const bare = (await get<{ install: { backup: Record<string, unknown> } }>("/api/v1/system/updates")).body.install.backup;
    expect(bare.recipient).toBe(true);
    expect(bare.skip_allowed).toBe(false);
    expect(bare.age_seconds).toBeUndefined();
  });
});

describe("an install without an answer about the backup", () => {
  it("is refused with 409 when the newest backup is older than an hour", async () => {
    const answer = await install();
    expect(answer.status).toBe(409);
    expect(answer.body.code).toBe("update.backup_required");
    expect(answer.body.params.max_age_seconds).toBe("3600");
    expect(Number(answer.body.params.age_seconds)).toBeGreaterThanOrEqual(3 * 86_400);
    expect(answer.body.params.skip_allowed).toBeUndefined();
    expect(mockUpdates.attempt).toBeNull();
    expect(mockUpdates.lastBackupPlan).toBeNull();
  });

  it("is refused with 409 and no age when there is no backup", async () => {
    backupState.runs = [];
    const answer = await install();
    expect(answer.status).toBe(409);
    expect(answer.body.code).toBe("update.backup_required");
    expect(answer.body.params.age_seconds).toBeUndefined();
  });

  it("does not count a failed backup", async () => {
    backupState.runs = [{ ...backupState.runs[0]!, outcome: "failed", finished_at: iso(Date.now() - 60_000) }];
    expect((await install()).status).toBe(409);
  });

  it("starts with 202 when a good backup is younger than an hour", async () => {
    backedUp(12 * 60_000);
    const answer = await install();
    expect(answer.status).toBe(202);
    expect(answer.body.version).toBe("0.2.0");
    expect(mockUpdates.lastBackupPlan).toBe("recent");
    expect(backupState.runs).toHaveLength(1);
  });

  it("is refused again just past the limit", async () => {
    backedUp(HOUR + 5_000);
    expect((await install()).status).toBe(409);
  });
});

describe("an install with \"skip\"", () => {
  it("starts with 202 and takes no backup", async () => {
    const answer = await install({ backup: "skip" });
    expect(answer.status).toBe(202);
    expect(mockUpdates.lastBackupPlan).toBe("skipped");
    expect(backupState.runs).toHaveLength(1);
  });

  it("is refused under the Hardened profile and says that a skip is not allowed", async () => {
    db.settings.profile = "hardened";
    // The profile also limits installs to a file; the server fetches again in this arrangement.
    db.settings.updates = { check: true, install: "ui" };
    const answer = await install({ backup: "skip" });
    expect(answer.status).toBe(409);
    expect(answer.body.code).toBe("update.backup_required");
    expect(answer.body.params.skip_allowed).toBe("false");
    expect(mockUpdates.attempt).toBeNull();
  });
});

describe("an install with \"run\"", () => {
  it("is refused with 422 without a recipient", async () => {
    const answer = await install({ backup: "run" });
    expect(answer.status).toBe(422);
    expect(answer.body.code).toBe("backup.key.missing");
    expect(mockUpdates.attempt).toBeNull();
    expect(backupState.runs).toHaveLength(1);
  });

  it("writes a backup with the reason before_update and the version, and adds the job step", async () => {
    backupState.settings.recipient = RECIPIENT;
    const answer = await install({ backup: "run" });
    expect(answer.status).toBe(202);
    expect(mockUpdates.lastBackupPlan).toBe("run");
    expect(backupState.runs).toHaveLength(2);
    const written = backupState.runs.find((r) => r.reason === "before_update");
    expect(written).toMatchObject({ before_update: "0.2.0", outcome: "succeeded", slots: ["recipient"] });

    const job = await get<{ job: { steps: { kind: string }[] } }>(`/api/v1/jobs/${answer.body.job_id}`);
    expect(job.body.job.steps.map((s) => s.kind)).toEqual([
      "sys.update.backup",
      "sys.update.fetch",
      "sys.update.verify",
      "sys.update.check",
      "sys.update.switch",
    ]);
  });

  it("starts nothing when the backup fails", async () => {
    backupState.settings.recipient = RECIPIENT;
    backupState.failNext = "backup.io";
    const answer = await install({ backup: "run" });
    expect(answer.status).toBe(500);
    expect(answer.body.code).toBe("backup.io");
    expect(mockUpdates.attempt).toBeNull();
    expect(backupState.runs[0]?.outcome).toBe("failed");
  });
});

describe("a value that is no answer", () => {
  it("is refused as an invalid value", async () => {
    const answer = await install({ backup: "maybe" });
    expect(answer.status).toBe(400);
    expect(answer.body.code).toBe("sys.invalid_value");
  });
});
