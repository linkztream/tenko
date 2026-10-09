// The audit log of the mock API: list, record and chain verification (IAM-18). The answers
// and error codes follow `crates/tenko-api/src/routes/audit.rs`: every signed-in role may
// read the log (it needs the `read` right on the system object, which viewers have).
import type { HttpHandler } from "msw";
import type { AuditRecord, ObjectKind } from "../types";
import { OBJECT_KINDS, audit, principalSubject, verifyAudit } from "./audit-store";
import { requireSession } from "./auth";
import { db } from "./db";
import { checkAtLeast, checkLimit, invalidQuery, onlyParams, singleParam } from "./routes-jobs";
import { Problem, ok } from "./reply";
import { paginate, route } from "./route";
import { isUuid } from "./util";

const LIST_PARAMS = ["principal", "action", "object", "outcome", "from", "to", "order", "limit", "cursor", "at_least"];

// ---------------------------------------------------------------------------------
// Filters

/** One name segment: lowercase letters, digits, `_` and `-`. */
const SEGMENT = /^[a-z0-9_-]+$/;

function validAction(name: string): boolean {
  const segments = name.split(".");
  return name.length <= 128 && segments.length >= 2 && segments.every((s) => SEGMENT.test(s));
}

interface Filter {
  principal: string | null;
  action: { text: string; prefix: boolean } | null;
  object: { kind: ObjectKind; id: string | null } | null;
  outcome: "success" | "denied" | "failed" | null;
  from: number | null;
  to: number | null;
  order: "asc" | "desc";
}

const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

function parseTime(url: URL, name: string): number | null {
  const raw = singleParam(url, name);
  if (raw === null) return null;
  const at = RFC3339.test(raw) ? Date.parse(raw) : Number.NaN;
  if (Number.isNaN(at)) return invalidQuery(name, "expected an RFC 3339 time such as 2026-10-09T12:00:00Z");
  return at;
}

function parseFilter(url: URL): Filter {
  const principal = singleParam(url, "principal");

  const rawAction = singleParam(url, "action");
  let action: Filter["action"] = null;
  if (rawAction !== null) {
    const prefix = rawAction.endsWith(".");
    // Some action starts with a prefix exactly when the prefix plus one more character is an action.
    if (!validAction(prefix ? `${rawAction}x` : rawAction)) {
      invalidQuery("action", `\`${rawAction}\` is not an action such as \`ipam.prefix.create\` or a prefix such as \`ipam.\``);
    }
    action = { text: rawAction, prefix };
  }

  const rawObject = singleParam(url, "object");
  let object: Filter["object"] = null;
  if (rawObject !== null) {
    const colon = rawObject.indexOf(":");
    const kind = colon < 0 ? rawObject : rawObject.slice(0, colon);
    if (!(OBJECT_KINDS as readonly string[]).includes(kind)) invalidQuery("object", `\`${kind}\` is not an object kind`);
    let id: string | null = null;
    if (colon >= 0) {
      id = rawObject.slice(colon + 1);
      if (!isUuid(id)) invalidQuery("object", `\`${id}\` is not a UUID; expected \`kind:uuid\``);
      id = id.toLowerCase();
    }
    object = { kind: kind as ObjectKind, id };
  }

  const rawOutcome = singleParam(url, "outcome");
  if (rawOutcome !== null && rawOutcome !== "success" && rawOutcome !== "denied" && rawOutcome !== "failed") {
    invalidQuery("outcome", "expected success, denied or failed");
  }

  const rawOrder = singleParam(url, "order");
  if (rawOrder !== null && rawOrder !== "asc" && rawOrder !== "desc") invalidQuery("order", "expected asc or desc");

  return {
    principal,
    action,
    object,
    outcome: rawOutcome as Filter["outcome"],
    from: parseTime(url, "from"),
    to: parseTime(url, "to"),
    order: rawOrder === "asc" ? "asc" : "desc",
  };
}

function matches(filter: Filter, record: AuditRecord): boolean {
  const draft = record.draft;
  const at = Date.parse(record.at);
  if (filter.from !== null && at < filter.from) return false;
  if (filter.to !== null && at >= filter.to) return false;
  if (filter.outcome !== null && draft.outcome.kind !== filter.outcome) return false;
  if (filter.action) {
    const { text, prefix } = filter.action;
    if (prefix ? !draft.action.startsWith(text) : draft.action !== text) return false;
  }
  const wanted = filter.object;
  if (wanted) {
    const objects = draft.objects ?? [];
    if (!objects.some((o) => o.kind === wanted.kind && (wanted.id === null || o.id.toLowerCase() === wanted.id))) return false;
  }
  if (filter.principal !== null && principalSubject(record.principal) !== filter.principal) return false;
  return true;
}

// ---------------------------------------------------------------------------------
// Routes

const listAudit = route("get", "/api/v1/audit", (ctx) => {
  requireSession();
  onlyParams(ctx.url, LIST_PARAMS);
  checkLimit(ctx.url);
  checkAtLeast(ctx.url);
  const filter = parseFilter(ctx.url);
  const rows = audit.records.filter((record) => matches(filter, record));
  rows.sort((a, b) => (filter.order === "asc" ? a.seq - b.seq : b.seq - a.seq));
  return ok(paginate(rows, ctx.url, db.revision));
});

const verify = route("get", "/api/v1/audit/verify", () => {
  requireSession();
  return ok(verifyAudit());
});

const MAX_SEQ = 2n ** 64n - 1n;

const getRecord = route("get", "/api/v1/audit/{seq}", (ctx) => {
  requireSession();
  const text = ctx.params.seq;
  const seq = /^\d+$/.test(text) ? BigInt(text) : 0n;
  if (seq < 1n || seq > MAX_SEQ) invalidQuery("seq", "must be a positive integer");
  const record = audit.records.find((r) => BigInt(r.seq) === seq);
  if (!record) {
    throw new Problem("sys.audit.not_found", {
      status: 404,
      detail: `audit record ${seq} does not exist`,
      params: { seq: String(seq) },
    });
  }
  return ok(record);
});

// `verify` first: the static segment must win over `{seq}`.
export const auditRoutes: HttpHandler[] = [verify, listAudit, getRecord];
