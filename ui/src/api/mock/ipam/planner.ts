// The planner: turns a list of commands into the changes they make on a copy of the state,
// the warnings they raise and the summary a person reviews (API-09); and the commit that
// applies a plan: swap in the new state, write history, audit records and the inline job,
// announce the change and raise the alarm events. A command that fails fails the whole
// list, so a bulk change applies completely or not at all (API-04).
import type {
  ChangeAction,
  HistoryEntry,
  IpamCommand,
  IpamObject,
  ObjectRef,
  PlanSummary,
  PlanView,
  PlanWarning,
  PlannedChange,
  Principal,
  SummaryCount,
} from "../../types";
import { appendAudit, principalNow } from "../audit-store";
import { db, recordEvent } from "../db";
import { recordInlineJob } from "../job-store";
import { Problem } from "../reply";
import { randomId } from "../util";
import { Body, isJson, type Json } from "./input";
import {
  createCustomField,
  createSite,
  createTenant,
  createVlan,
  createVrf,
  customFieldKeyOf,
  deleteCustomField,
  deleteSite,
  deleteTenant,
  deleteVlan,
  deleteVrf,
  restoreSite,
  restoreTenant,
  restoreVlan,
  restoreVrf,
  updateCustomField,
  updateSite,
  updateTenant,
  updateVlan,
  updateVrf,
} from "./plan-tenancy";
import {
  allocateAddress,
  allocatePrefix,
  createAddress,
  createPrefix,
  createRange,
  deleteAddress,
  deletePrefix,
  deleteRange,
  restoreAddress,
  restorePrefix,
  restoreRange,
  updateAddress,
  updatePrefix,
  updateRange,
} from "./plan-space";
import {
  checkReservations,
  createHost,
  createInterface,
  deleteHost,
  deleteInterface,
  restoreHost,
  restoreInterface,
  setLock,
  setMode,
  updateHost,
  updateInterface,
} from "./plan-hosts";
import { invalid, planUnacknowledged } from "./problems";
import { lookup, store, type Kind } from "./state";
import { allLevels } from "./tree";
import { Workspace } from "./workspace";

/** The most commands one request may carry (`IpamConfig::max_commands`). */
export const MAX_COMMANDS = 10_000;

/** A command as received: the operation and its still unchecked arguments. */
export interface RawCommand {
  op: string;
  args: Json;
}

type Handler = (ws: Workspace, args: Json) => ObjectRef;

/** Reads the members of a `delete` or `restore` command. */
function objectOf(args: Json): { kind: string; id: string; body: Body } {
  const body = new Body(args);
  const object = body.reqObject("object");
  const inner = new Body(object, "object.").only(["id", "kind"]);
  const kind = inner.string("kind") ?? "";
  const id = inner.reqUuid("id");
  body.absorb(inner);
  return { kind, id, body };
}

function deleteCommand(ws: Workspace, args: Json): ObjectRef {
  const { kind, id, body } = objectOf(args);
  body.only(["cascade", "expected", "object"]);
  const cascade = body.bool("cascade") ?? false;
  const expected = body.expected();
  body.done();
  switch (kind) {
    case "tenant":
      return deleteTenant(ws, id, expected);
    case "vrf":
      return deleteVrf(ws, id, expected);
    case "site":
      return deleteSite(ws, id, expected);
    case "vlan":
      return deleteVlan(ws, id, expected);
    case "prefix":
      return deletePrefix(ws, id, expected, cascade);
    case "range":
      return deleteRange(ws, id, expected);
    case "address":
      return deleteAddress(ws, id, expected);
    case "host":
      return deleteHost(ws, id, expected, cascade);
    case "interface":
      return deleteInterface(ws, id, expected, cascade);
    case "custom_field":
      return deleteCustomField(ws, customFieldKeyOf(ws, id), expected);
    default:
      throw invalid("object", `${kind || "this kind of"} objects are not managed by IPAM`);
  }
}

function restoreCommand(ws: Workspace, args: Json): ObjectRef {
  const { kind, id, body } = objectOf(args);
  body.only(["expected", "object"]);
  const expected = body.expected();
  body.done();
  switch (kind) {
    case "tenant":
      return restoreTenant(ws, id, expected);
    case "vrf":
      return restoreVrf(ws, id, expected);
    case "site":
      return restoreSite(ws, id, expected);
    case "vlan":
      return restoreVlan(ws, id, expected);
    case "prefix":
      return restorePrefix(ws, id, expected);
    case "range":
      return restoreRange(ws, id, expected);
    case "address":
      return restoreAddress(ws, id, expected);
    case "host":
      return restoreHost(ws, id, expected);
    case "interface":
      return restoreInterface(ws, id, expected);
    default:
      throw invalid("object", `${kind || "this kind of"} objects cannot be restored`);
  }
}

const HANDLERS: Readonly<Record<string, Handler>> = {
  create_tenant: createTenant,
  update_tenant: updateTenant,
  create_vrf: createVrf,
  update_vrf: updateVrf,
  create_site: createSite,
  update_site: updateSite,
  create_vlan: createVlan,
  update_vlan: updateVlan,
  create_prefix: createPrefix,
  update_prefix: updatePrefix,
  create_range: createRange,
  update_range: updateRange,
  create_address: createAddress,
  update_address: updateAddress,
  create_host: createHost,
  update_host: updateHost,
  create_interface: createInterface,
  update_interface: updateInterface,
  delete: deleteCommand,
  restore: restoreCommand,
  set_lock: setLock,
  set_mode: setMode,
  allocate_address: allocateAddress,
  allocate_prefix: allocatePrefix,
  create_custom_field: createCustomField,
  update_custom_field: updateCustomField,
  delete_custom_field: (ws, args) => {
    const body = new Body(args).only(["expected", "key"]);
    const key = body.reqString("key");
    const expected = body.expected();
    body.done();
    return deleteCustomField(ws, key, expected);
  },
};

/** The kind of object a command changes, for the collection check of a bulk request. */
export function commandKind(command: RawCommand): Kind | null {
  const { op, args } = command;
  const named = /^(?:create|update)_(.+)$/.exec(op);
  if (named) return (named[1] ?? null) as Kind | null;
  switch (op) {
    case "delete":
    case "restore": {
      const object = args.object;
      return isJson(object) && typeof object.kind === "string" ? (object.kind as Kind) : null;
    }
    case "set_lock":
    case "set_mode":
      return "host";
    case "allocate_address":
      return "address";
    case "allocate_prefix":
      return "prefix";
    case "delete_custom_field":
      return "custom_field";
    default:
      return null;
  }
}

function runCommand(ws: Workspace, command: RawCommand): ObjectRef {
  const handler = HANDLERS[command.op];
  if (!handler) {
    throw new Problem("sys.invalid_request", {
      status: 400,
      detail: `unknown variant \`${command.op}\``,
      params: { part: "body" },
    });
  }
  return handler(ws, command.args);
}

// ---------------------------------------------------------------------------------
// Plans

export interface PlanOptions {
  /** Warning codes the caller acknowledges. */
  acknowledge?: Iterable<string> | undefined;
  /** Who acts; the signed-in user by default. */
  principal?: Principal | undefined;
}

export interface Plan {
  /** The revision the plan was computed from. */
  base: number;
  at: string;
  request: string;
  principal: Principal;
  ws: Workspace;
  changes: PlannedChange[];
  warnings: PlanWarning[];
  results: ObjectRef[];
}

/**
 * Plans the commands against the current state without writing anything. Throws the first
 * `Problem` a command raises.
 */
export function planCommands(commands: readonly RawCommand[], options: PlanOptions = {}): Plan {
  if (commands.length > MAX_COMMANDS) {
    throw new Problem("ipam.bulk.too_large", {
      status: 413,
      detail: `${commands.length} operations exceed the limit of ${MAX_COMMANDS}`,
      params: { count: String(commands.length), limit: String(MAX_COMMANDS) },
    });
  }
  const principal = options.principal ?? principalNow();
  const ws = new Workspace(store.data, new Date().toISOString(), principal);
  const results = commands.map((command) => runCommand(ws, command));
  checkReservations(ws);
  const acknowledge = new Set(options.acknowledge ?? []);
  for (const warning of ws.warnings) warning.acknowledged = warning.requires_ack === true && acknowledge.has(warning.code);
  return {
    base: db.revision,
    at: ws.at,
    request: randomId(),
    principal,
    ws,
    changes: ws.changes,
    warnings: ws.warnings,
    results,
  };
}

/** The warning codes that need an acknowledgement and did not get one. */
export function unacknowledged(plan: Plan): string[] {
  const codes = new Set<string>();
  for (const warning of plan.warnings) if (warning.requires_ack && !warning.acknowledged) codes.add(warning.code);
  return [...codes].sort();
}

const ACTIONS: readonly ChangeAction[] = ["create", "update", "delete", "restore", "lock", "unlock", "remove"];
const PAST: Readonly<Record<ChangeAction, string>> = {
  create: "created",
  update: "updated",
  delete: "deleted",
  restore: "restored",
  lock: "locked",
  unlock: "unlocked",
  remove: "removed",
};

function noun(kind: string, count: number): string {
  const singular = kind === "custom_field" ? "custom field" : kind === "vrf" ? "VRF" : kind === "vlan" ? "VLAN" : kind;
  if (count === 1) return singular;
  if (singular.endsWith("ss")) return `${singular}es`;
  if (singular.endsWith("x")) return `${singular.slice(0, -1)}xes`;
  return `${singular}s`;
}

function summarize(plan: Plan): PlanSummary {
  const counts = new Map<string, SummaryCount>();
  for (const change of plan.changes) {
    const key = `${change.object.kind}/${change.action}`;
    const entry = counts.get(key);
    if (entry) entry.count += 1;
    else counts.set(key, { kind: change.object.kind, action: change.action, count: 1 });
  }
  const ordered = [...counts.values()].sort((a, b) =>
    a.kind === b.kind ? ACTIONS.indexOf(a.action) - ACTIONS.indexOf(b.action) : a.kind < b.kind ? -1 : 1,
  );
  const warnings: Record<string, number> = {};
  for (const warning of plan.warnings) warnings[warning.code] = (warnings[warning.code] ?? 0) + 1;
  const lines = ordered.map((c) => `${c.count} ${noun(c.kind, c.count)} ${PAST[c.action]}`);
  if (lines.length === 0) lines.push("no changes");
  for (const [code, count] of Object.entries(warnings).sort(([a], [b]) => (a < b ? -1 : 1))) {
    lines.push(`${count} warning${count === 1 ? "" : "s"}: ${code}`);
  }
  const touched = new Set(plan.changes.map((c) => `${c.object.kind}/${c.object.id}`));
  return {
    counts: ordered,
    warnings,
    unacknowledged: unacknowledged(plan),
    lines,
    mutations: plan.changes.length * 2,
    preconditions: touched.size,
  };
}

/** The reviewable part of a plan: the answer of a dry run (API-09). */
export function planView(plan: Plan): PlanView {
  return {
    base_revision: plan.base,
    changes: plan.changes,
    results: plan.results,
    summary: summarize(plan),
    warnings: plan.warnings,
  };
}

// ---------------------------------------------------------------------------------
// Commit

export interface Applied {
  /** The revision that committed the plan; the current one when the plan changed nothing. */
  revision: number;
  jobId: string | null;
}

/** Emits an alarm event for every prefix whose level changed with the last write. */
function raiseAlarms(): void {
  const next = allLevels(store.data);
  for (const [id, now] of next) {
    const previous = store.levels.get(id) ?? "normal";
    store.levels.set(id, now.level);
    if (now.level === previous) continue;
    recordEvent("system", {
      objects: [{ kind: "prefix", id }],
      tables: ["ipam.alarms"],
      kind: "ipam.prefix.alarm",
      params: { cidr: now.cidr, level: now.level, previous, percent: String(now.percent) },
    });
  }
  for (const [id, previous] of [...store.levels]) {
    if (next.has(id)) continue;
    store.levels.delete(id);
    if (previous === "normal") continue;
    recordEvent("system", {
      objects: [{ kind: "prefix", id }],
      tables: ["ipam.alarms"],
      kind: "ipam.prefix.alarm",
      params: { cidr: store.data.prefix.get(id)?.cidr ?? "", level: "normal", previous, percent: "0" },
    });
  }
}

function stampRevision(ref: ObjectRef, revision: number): void {
  if (ref.kind === "custom_field") {
    if (store.data.custom_field.has(ref.id)) store.data.fieldRevisions.set(ref.id, revision);
    return;
  }
  const found = (store.data[ref.kind as Exclude<Kind, "custom_field">] as Map<string, { meta: { revision?: number } }>).get(ref.id);
  if (found) found.meta.revision = revision;
}

/**
 * Applies a plan: the new state replaces the old one, the history, the audit log and the
 * jobs record the change, and one `ipam` event announces it. Fails with
 * `ipam.plan.unacknowledged` while a warning still needs its acknowledgement.
 */
export function commitPlan(plan: Plan): Applied {
  const missing = unacknowledged(plan);
  if (missing.length > 0) throw planUnacknowledged(missing);
  if (plan.changes.length === 0) return { revision: db.revision, jobId: null };

  store.data = plan.ws.data;
  const entries: HistoryEntry[] = plan.changes.map((change) => ({
    object: change.object,
    action: change.action,
    at: plan.at,
    by: plan.principal,
    request: plan.request,
    ...(change.before ? { before: change.before } : {}),
    ...(change.after ? { after: change.after } : {}),
    ...(change.fields ? { changes: change.fields } : {}),
    job_kind: "ipam.apply",
    revision: 0,
  }));
  for (const [index, change] of plan.changes.entries()) {
    const list = store.history.get(change.object.id);
    const entry = entries[index] as HistoryEntry;
    if (list) list.push(entry);
    else store.history.set(change.object.id, [entry]);
    appendAudit({
      action: `ipam.${change.object.kind}.${change.action}`,
      objects: [change.object],
      changes: change.fields ?? [],
      context: change.derived ? { derived: "true" } : {},
      principal: plan.principal,
    });
  }

  const seen = new Set<string>();
  const objects: ObjectRef[] = [];
  const deleted: ObjectRef[] = [];
  for (const change of plan.changes) {
    const key = `${change.object.kind}/${change.object.id}`;
    if (change.action === "remove") {
      if (!deleted.some((d) => d.id === change.object.id)) deleted.push(change.object);
    } else if (!seen.has(key)) {
      seen.add(key);
      objects.push(change.object);
    }
  }
  const targets = [...objects, ...deleted];
  const jobId = recordInlineJob({ kind: "ipam.apply", title: "jobs.title.ipam_apply", targets });
  const tables = [...new Set(targets.map((t) => `ipam.${t.kind}`))].sort();
  const event = recordEvent("ipam", { objects, deleted, tables });
  const revision = event.id ?? db.revision;
  for (const ref of objects) stampRevision(ref, revision);
  for (const entry of entries) entry.revision = revision;
  raiseAlarms();
  return { revision, jobId };
}

// ---------------------------------------------------------------------------------
// Executing

export interface ExecuteOptions extends PlanOptions {
  /** Plan only: nothing is written. */
  dryRun?: boolean | undefined;
}

export interface Outcome {
  dryRun: boolean;
  plan: Plan;
  view: PlanView;
  /** The revision that committed the change; null on a dry run. */
  revision: number | null;
  jobId: string | null;
  results: ObjectRef[];
  warnings: PlanWarning[];
}

/** Plans the commands and, unless it is a dry run, applies them. */
export function execute(commands: readonly RawCommand[], options: ExecuteOptions = {}): Outcome {
  const plan = planCommands(commands, options);
  const view = planView(plan);
  if (options.dryRun) {
    return { dryRun: true, plan, view, revision: null, jobId: null, results: plan.results, warnings: plan.warnings };
  }
  const applied = commitPlan(plan);
  return {
    dryRun: false,
    plan,
    view,
    revision: applied.revision,
    jobId: applied.jobId,
    results: plan.results,
    warnings: plan.warnings,
  };
}

/** The object a result points at: as it would be (dry run) or as it is now (applied). */
export function itemOf(outcome: Outcome, ref: ObjectRef): IpamObject | null {
  if (outcome.dryRun) {
    for (let i = outcome.plan.changes.length - 1; i >= 0; i -= 1) {
      const change = outcome.plan.changes[i] as PlannedChange;
      if (change.object.kind === ref.kind && change.object.id === ref.id) return change.after ?? null;
    }
    return null;
  }
  const found = lookup(store.data, ref);
  return found ? structuredClone(found) : null;
}

// ---------------------------------------------------------------------------------
// For other mock modules

export interface ApplyOptions {
  /** Warning codes to acknowledge. */
  acknowledge?: readonly string[];
  /** Plan only. */
  dryRun?: boolean;
  /** Who acts; the signed-in user by default. */
  principal?: Principal;
}

export interface ApplyResult {
  dry_run: boolean;
  /** The revision that committed the change; null on a dry run. */
  revision: number | null;
  job_id: string | null;
  /** The primary object of each command. */
  results: ObjectRef[];
  /** The primary objects as they are now (or would be, on a dry run). */
  items: (IpamObject | null)[];
  warnings: PlanWarning[];
  plan: PlanView;
}

/**
 * Applies commands through the same planner as the HTTP handlers: validation, conflicts,
 * warnings, history, audit, the inline job and the events. Throws a `Problem` when a
 * command fails; then nothing changed.
 */
export function applyCommands(commands: readonly IpamCommand[], options: ApplyOptions = {}): ApplyResult {
  const outcome = execute(commands as unknown as readonly RawCommand[], options);
  return {
    dry_run: outcome.dryRun,
    revision: outcome.revision,
    job_id: outcome.jobId,
    results: outcome.results,
    items: outcome.results.map((ref) => itemOf(outcome, ref)),
    warnings: outcome.warnings,
    plan: outcome.view,
  };
}
