// The audit log of the mock API (IAM-18): sealed records with a hash chain, appended by
// every mock write that the server would audit. The hashes are test values computed with a
// small non-cryptographic digest; they only have to link, not to protect anything.
import type {
  AuditDraft,
  AuditOutcome,
  AuditRecord,
  AuditVerifyReport,
  FieldChange,
  ObjectKind,
  ObjectRef,
  Principal,
} from "../types";
import { db, onMockReset, recordEvent } from "./db";
import { MOCK_USER_IDS } from "./fixtures";
import { HOUR_MS, iso } from "./util";

export interface AuditInput {
  action: string;
  objects?: ObjectRef[];
  changes?: FieldChange[];
  context?: Record<string, string>;
  outcome?: AuditOutcome;
  /** Who acted; the signed-in user of the mock by default (see principalNow). */
  principal?: Principal;
  /** The client address; a documentation address by default, null for work of the system. */
  source_ip?: string | null;
  /** Milliseconds since the epoch; now by default. */
  at?: number;
}

const ZERO = "0".repeat(64);
const NIL = "00000000-0000-0000-0000-000000000000";

/** Every kind of object of the document. */
export const OBJECT_KINDS: readonly ObjectKind[] = [
  "tenant",
  "vrf",
  "site",
  "vlan",
  "prefix",
  "range",
  "address",
  "host",
  "interface",
  "custom_field",
  "user",
  "session",
  "api_token",
  "job",
  "observation",
  "proposal",
  "import",
  "connector",
  "secret",
  "node",
  "settings",
  "system",
  "zone",
  "dns_view",
  "dns_forwarder",
  "dns_acl",
  "dns_key",
  "dns_list",
];

/** The records, oldest first; `seq` starts at 1 and has no gaps. */
export const audit: { records: AuditRecord[] } = { records: [] };

/** A 64-hex-digit test digest of a text (FNV-1a over eight lanes; not cryptographic). */
export function testDigest(text: string): string {
  let out = "";
  for (let lane = 0; lane < 8; lane += 1) {
    let h = 0x811c9dc5 ^ (lane * 0x9e3779b1);
    for (let i = 0; i < text.length; i += 1) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    out += (h >>> 0).toString(16).padStart(8, "0");
  }
  return out;
}

/** The hash a record must carry: the digest over the fields the hash covers. */
export function recordDigest(record: Pick<AuditRecord, "seq" | "revision" | "at" | "prev" | "draft" | "principal">): string {
  return testDigest(
    `${record.seq}|${record.revision}|${record.at}|${record.prev}|${JSON.stringify(record.draft)}|${JSON.stringify(record.principal)}`,
  );
}

/** The principal of the signed-in mock user, or the IPAM system component without one. */
export function principalNow(): Principal {
  const session = db.sessions.find((s) => s.id === db.currentSessionId);
  if (!session) return { kind: "system", component: "ipam" } as Principal;
  return { kind: "user", id: session.user_id, session: session.id, strength: session.strength } as Principal;
}

/** The subject string of a principal: `user:<id>`, `token:<id>`, `system:<component>`, `node:<id>`. */
export function principalSubject(principal: Principal): string {
  switch (principal.kind) {
    case "user":
      return `user:${principal.id}`;
    case "token":
      return `token:${principal.id}`;
    case "system":
      return `system:${principal.component}`;
    case "node":
      return `node:${principal.id}`;
  }
}

function seal(
  seq: number,
  revision: number,
  at: string,
  principal: Principal,
  input: AuditInput,
  prev: string,
): AuditRecord {
  const draft: AuditDraft = {
    action: input.action,
    objects: input.objects ?? [],
    outcome: input.outcome ?? { kind: "success" },
    details: { changes: input.changes ?? [], context: input.context ?? {} },
    source_ip: input.source_ip === undefined ? "192.0.2.50" : input.source_ip,
  };
  const record: AuditRecord = { seq, at, draft, principal, prev, revision, hash: "" };
  record.hash = recordDigest(record);
  return record;
}

/** Appends one record and announces it on the `audit` topic; returns its sequence number. */
export function appendAudit(input: AuditInput): number {
  const prev = audit.records[audit.records.length - 1];
  const seq = (prev?.seq ?? 0) + 1;
  const at = new Date(input.at ?? Date.now()).toISOString();
  const event = recordEvent("audit", { audit: [seq] });
  const record = seal(seq, event.id ?? db.revision, at, input.principal ?? principalNow(), input, prev?.hash ?? ZERO);
  audit.records.push(record);
  return seq;
}

/**
 * Walks the chain from seq 1 like `GET /audit/verify` of the server: the first record that
 * leaves a gap, does not link to its predecessor or does not match its hash ends the walk.
 */
export function verifyAudit(): AuditVerifyReport {
  let checked = 0;
  let head = { seq: 0, hash: ZERO };
  let firstBreak: AuditVerifyReport["first_break"] = null;
  for (const record of audit.records) {
    if (record.seq !== head.seq + 1) {
      firstBreak = {
        seq: record.seq,
        code: "sys.audit.gap",
        detail: `audit chain gap: expected record ${head.seq + 1}, found ${record.seq}`,
      };
    } else if (record.prev !== head.hash) {
      firstBreak = {
        seq: record.seq,
        code: "sys.audit.broken_link",
        detail: `audit record ${record.seq} does not link to its predecessor`,
      };
    } else if (recordDigest(record) !== record.hash) {
      firstBreak = {
        seq: record.seq,
        code: "sys.audit.bad_hash",
        detail: `audit record ${record.seq} has been altered`,
      };
    }
    if (firstBreak) break;
    checked += 1;
    head = { seq: record.seq, hash: record.hash };
  }
  const report: AuditVerifyReport = {
    intact: firstBreak === null,
    checked,
    head,
    store_head: audit.records[audit.records.length - 1]?.seq ?? 0,
    revision: db.revision,
  };
  if (firstBreak) report.first_break = firstBreak;
  return report;
}

/**
 * Changes the stored hash of a record, so that `GET /audit/verify` reports
 * `sys.audit.bad_hash` at `seq`. For tests of the broken-chain state.
 */
export function tamperAuditRecord(seq: number): void {
  const record = audit.records.find((r) => r.seq === seq);
  if (!record) throw new Error(`no audit record ${seq}`);
  record.hash = `${record.hash.startsWith("0") ? "1" : "0"}${record.hash.slice(1)}`;
}

// ---------------------------------------------------------------------------------
// Seeds

/** Ids of the objects the seed records name (UUID syntax, like the real ones). */
export const AUDIT_SEED_IDS = {
  settings: NIL,
  prefixLan: "0190d1c2-0000-7000-8000-0000000a0001",
  prefixIot: "0190d1c2-0000-7000-8000-0000000a0002",
  prefixLab: "0190d1c2-0000-7000-8000-0000000a0003",
  hostNas: "0190d1c2-0000-7000-8000-0000000b0004",
  hostThermostat: "0190d1c2-0000-7000-8000-0000000b0001",
  hostCamDoor: "0190d1c2-0000-7000-8000-0000000b0003",
  address35: "0190d1c2-0000-7000-8000-0000000a0135",
  jobRolledBack: "0190d1c2-0000-7000-8000-0000000c0005",
  jobCancelled: "0190d1c2-0000-7000-8000-0000000c0006",
} as const;

/** The notes a person left on the steps of the rolled back seed job (job-store.ts seeds them too). */
export const SEED_ROLLBACK_NOTES = {
  dhcp: "Reserved 198.51.100.43 for cam-door in the DHCP server.",
  dns: "Updated the A record of cam-door.example.test.",
} as const;

const ALEX: Principal = {
  kind: "user",
  id: MOCK_USER_IDS.alex,
  session: "0190d1c2-0000-7000-8000-0000000e0001",
  strength: "passkey",
};
const SAM: Principal = {
  kind: "user",
  id: MOCK_USER_IDS.sam,
  session: "0190d1c2-0000-7000-8000-0000000e0002",
  strength: "password",
};
const SYSTEM_IPAM: Principal = { kind: "system", component: "ipam" };
const SYSTEM_JOBS: Principal = { kind: "system", component: "jobs" };
const SYSTEM_AUTH: Principal = { kind: "system", component: "auth" };

interface SeedRow {
  /** Hours before the reset. */
  ago: number;
  who: Principal;
  input: Omit<AuditInput, "principal" | "at">;
}

const prefix = (id: string): ObjectRef[] => [{ kind: "prefix", id }];
const host = (id: string): ObjectRef[] => [{ kind: "host", id }];
const job = (id: string): ObjectRef[] => [{ kind: "job", id }];
const user = (id: string): ObjectRef[] => [{ kind: "user", id }];

const created = (field: string, value: string): FieldChange => ({ field, old: null, new: value });
const NO_SOURCE = { source_ip: null } as const;

/** About forty records over the last seven days. */
const SEED_ROWS: readonly SeedRow[] = [
  { ago: 167.5, who: ALEX, input: { action: "auth.login.success", objects: user(MOCK_USER_IDS.alex), context: { method: "passkey" } } },
  {
    ago: 167.2,
    who: ALEX,
    input: {
      action: "settings.security.update",
      objects: [{ kind: "settings", id: AUDIT_SEED_IDS.settings }],
      changes: [{ field: "TGL-02", old: "on", new: "off" }],
    },
  },
  {
    ago: 166,
    who: ALEX,
    input: {
      action: "users.user.create",
      objects: user(MOCK_USER_IDS.sam),
      changes: [created("name", "sam"), created("roles", "operator")],
    },
  },
  {
    ago: 165.5,
    who: ALEX,
    input: {
      action: "users.user.create",
      objects: user(MOCK_USER_IDS.robin),
      changes: [created("name", "robin"), created("roles", "viewer")],
    },
  },
  {
    ago: 160,
    who: ALEX,
    input: {
      action: "ipam.prefix.create",
      objects: prefix(AUDIT_SEED_IDS.prefixLan),
      changes: [created("cidr", "192.0.2.0/24"), created("status", "active")],
    },
  },
  {
    ago: 159.5,
    who: ALEX,
    input: {
      action: "ipam.prefix.create",
      objects: prefix(AUDIT_SEED_IDS.prefixIot),
      changes: [created("cidr", "198.51.100.0/24"), created("status", "active")],
    },
  },
  {
    ago: 159,
    who: ALEX,
    input: {
      action: "ipam.prefix.create",
      objects: prefix(AUDIT_SEED_IDS.prefixLab),
      changes: [created("cidr", "203.0.113.0/25"), created("status", "planned")],
    },
  },
  {
    ago: 158,
    who: ALEX,
    input: {
      action: "ipam.prefix.create",
      objects: prefix(AUDIT_SEED_IDS.prefixLan),
      context: { cidr: "192.0.2.128/25" },
      outcome: { kind: "failed", code: "ipam.prefix.overlap" },
    },
  },
  {
    ago: 150,
    who: ALEX,
    input: {
      action: "ipam.host.create",
      objects: host(AUDIT_SEED_IDS.hostNas),
      changes: [created("name", "nas.example.test"), created("mode", "static")],
    },
  },
  {
    ago: 149.8,
    who: ALEX,
    input: {
      action: "ipam.address.create",
      objects: [{ kind: "address", id: AUDIT_SEED_IDS.address35 }],
      changes: [created("ip", "192.0.2.35"), created("status", "active")],
    },
  },
  {
    ago: 149.5,
    who: ALEX,
    input: {
      action: "ipam.host.create",
      objects: host(AUDIT_SEED_IDS.hostThermostat),
      changes: [created("name", "thermostat-1.example.test"), created("mode", "static")],
    },
  },
  { ago: 147, who: SAM, input: { action: "auth.login.success", objects: user(MOCK_USER_IDS.sam), context: { method: "password" } } },
  {
    ago: 146,
    who: SAM,
    input: {
      action: "ipam.host.update",
      objects: host(AUDIT_SEED_IDS.hostNas),
      changes: [{ field: "mode", old: "static", new: "reserved" }],
    },
  },
  {
    ago: 144.5,
    who: SAM,
    input: {
      action: "ipam.host.update",
      objects: host(AUDIT_SEED_IDS.hostThermostat),
      changes: [{ field: "dns_name", old: "thermostat-1.example.test", new: "thermostat.example.test" }],
    },
  },
  { ago: 143.5, who: ALEX, input: { action: "auth.login.success", objects: user(MOCK_USER_IDS.alex), context: { method: "passkey" } } },
  {
    ago: 130,
    who: SYSTEM_AUTH,
    input: { action: "auth.login.failure", outcome: { kind: "denied" }, context: { user: "admin" }, source_ip: "203.0.113.77" },
  },
  {
    ago: 129.9,
    who: SYSTEM_AUTH,
    input: { action: "auth.login.failure", outcome: { kind: "denied" }, context: { user: "admin" }, source_ip: "203.0.113.77" },
  },
  {
    ago: 120,
    who: ALEX,
    input: {
      action: "settings.security.update",
      objects: [{ kind: "settings", id: AUDIT_SEED_IDS.settings }],
      changes: [{ field: "TGL-05", old: "administrators", new: "everyone" }],
    },
  },
  { ago: 119.5, who: ALEX, input: { action: "auth.login.success", objects: user(MOCK_USER_IDS.alex), context: { method: "passkey" } } },
  {
    ago: 100,
    who: ALEX,
    input: {
      action: "ipam.address.delete",
      objects: [{ kind: "address", id: AUDIT_SEED_IDS.address35 }],
      changes: [{ field: "ip", old: "192.0.2.35", new: null }],
    },
  },
  {
    ago: 99,
    who: SYSTEM_IPAM,
    input: {
      action: "ipam.prefix.alarm",
      objects: prefix(AUDIT_SEED_IDS.prefixIot),
      context: { level: "warning", utilization: "82" },
      ...NO_SOURCE,
    },
  },
  { ago: 95.5, who: ALEX, input: { action: "auth.login.success", objects: user(MOCK_USER_IDS.alex), context: { method: "passkey" } } },
  {
    ago: 94,
    who: ALEX,
    input: {
      action: "ipam.prefix.update",
      objects: prefix(AUDIT_SEED_IDS.prefixLab),
      changes: [{ field: "status", old: "planned", new: "active" }],
    },
  },
  {
    ago: 80,
    who: SAM,
    input: {
      action: "ipam.host.update",
      objects: host(AUDIT_SEED_IDS.hostCamDoor),
      changes: [{ field: "mode", old: "dynamic", new: "reserved" }],
    },
  },
  {
    ago: 75,
    who: SYSTEM_IPAM,
    input: {
      action: "ipam.prefix.alarm",
      objects: prefix(AUDIT_SEED_IDS.prefixIot),
      context: { level: "critical", utilization: "95" },
      ...NO_SOURCE,
    },
  },
  { ago: 71.5, who: ALEX, input: { action: "auth.login.success", objects: user(MOCK_USER_IDS.alex), context: { method: "passkey" } } },
  {
    ago: 70,
    who: ALEX,
    input: {
      action: "ipam.host.create",
      objects: host(AUDIT_SEED_IDS.hostCamDoor),
      changes: [created("name", "cam-door.example.test"), created("mode", "reserved")],
    },
  },
  { ago: 47.5, who: SAM, input: { action: "auth.login.success", objects: user(MOCK_USER_IDS.sam), context: { method: "password" } } },
  {
    ago: 40,
    who: SAM,
    input: {
      action: "ipam.address.create",
      objects: [{ kind: "address", id: AUDIT_SEED_IDS.address35 }],
      changes: [created("ip", "192.0.2.36"), created("status", "reserved")],
    },
  },
  { ago: 26.1, who: ALEX, input: { action: "auth.login.success", objects: user(MOCK_USER_IDS.alex), context: { method: "passkey" } } },
  { ago: 25.9, who: SAM, input: { action: "auth.login.success", objects: user(MOCK_USER_IDS.sam), context: { method: "password" } } },
  // The notes below are the ones the rolled back seed job carries.
  {
    ago: 25.8,
    who: SAM,
    input: {
      action: "jobs.step.complete",
      objects: job(AUDIT_SEED_IDS.jobRolledBack),
      context: { step: "1", note: SEED_ROLLBACK_NOTES.dhcp },
    },
  },
  {
    ago: 25.55,
    who: SAM,
    input: {
      action: "jobs.step.complete",
      objects: job(AUDIT_SEED_IDS.jobRolledBack),
      context: { step: "2", note: SEED_ROLLBACK_NOTES.dns },
    },
  },
  {
    ago: 25.545,
    who: SYSTEM_JOBS,
    input: {
      action: "jobs.job.roll_back",
      objects: job(AUDIT_SEED_IDS.jobRolledBack),
      outcome: { kind: "failed", code: "jobs.step.failed" },
      context: { kind: "ipam.move", error: "jobs.step.failed" },
      ...NO_SOURCE,
    },
  },
  {
    ago: 25.4,
    who: SAM,
    input: {
      action: "ipam.host.update",
      objects: host(AUDIT_SEED_IDS.hostCamDoor),
      changes: [{ field: "description", old: null, new: "Move rolled back: check the switch port first" }],
    },
  },
  {
    ago: 6,
    who: SYSTEM_IPAM,
    input: {
      action: "ipam.prefix.alarm",
      objects: prefix(AUDIT_SEED_IDS.prefixLan),
      context: { level: "warning", utilization: "81" },
      ...NO_SOURCE,
    },
  },
  { ago: 5.9, who: ALEX, input: { action: "auth.login.success", objects: user(MOCK_USER_IDS.alex), context: { method: "passkey" } } },
  {
    ago: 3,
    who: ALEX,
    input: { action: "jobs.job.cancel", objects: job(AUDIT_SEED_IDS.jobCancelled), context: { kind: "ipam.apply" } },
  },
  {
    ago: 1,
    who: ALEX,
    input: {
      action: "ipam.host.update",
      objects: host(AUDIT_SEED_IDS.hostNas),
      changes: [{ field: "dns_name", old: "nas.example.test", new: "storage.example.test" }],
    },
  },
];

function seedAudit(): void {
  const now = Date.now();
  const rows = [...SEED_ROWS].sort((a, b) => b.ago - a.ago);
  // The seeds count back from the revision of the reset, so that revisions stay unique.
  const first = db.revision - rows.length + 1;
  const records: AuditRecord[] = [];
  rows.forEach((row, index) => {
    const prev = records[index - 1];
    const at = iso(now - Math.round(row.ago * HOUR_MS));
    records.push(seal(index + 1, first + index, at, row.who, row.input, prev?.hash ?? ZERO));
  });
  audit.records = records;
}

function reseed(): void {
  const setup = db.scenario === "setup" || db.scenario === "setup-slow-disk";
  audit.records = [];
  if (!setup) seedAudit();
}

onMockReset(reseed);
reseed();
