// The evaluation behind a preview and an apply (crates/tenko-ipam/src/import/service.rs):
// translate the mapped sheets, reconcile the model with the IPAM state, plan the commands as
// a dry run, and describe all of it for the wizard: counts per kind and action, the first
// rows, the loss report by sheet, the proposals, what happens to credentials, the plan's
// warnings and what stops an apply.
import type { components } from "../generated/schema";
import { formatCidr, formatIp } from "../../ipam/ip";
import type { Principal } from "./auth";
import { testDigest } from "./audit-store";
import { db, isAdmin } from "./db";
import { Problem } from "./reply";
import { applyCommands, type ApplyResult } from "./ipam/api";
import type { Mapping } from "./import-mapping";
import { itemId, type ItemKey, type LossEntry } from "./import-model";
import { knownPrefixes, reconcile, type ItemAction, type ItemOutcome, type Reconciled } from "./import-reconcile";
import { vaultDigests, type ImportRecord } from "./import-store";
import { mockSecrets } from "./secrets-store";
import { translate, type Translation } from "./import-translate";
import { PROBLEM, severityOf, LOSS } from "./import-vocab";
import { STRENGTH_RANK } from "./auth";

type S = components["schemas"];
export type ImportPreview = S["ImportPreview"];

export interface Evaluation {
  mapping: Mapping;
  translation: Translation;
  reconciled: Reconciled;
  /** The dry-run plan, or the problem that stopped it. */
  plan: { ok: true; result: ApplyResult } | { ok: false; problem: Problem };
}

/** Plans the import without writing anything. */
export function evaluate(record: ImportRecord, acknowledge: readonly string[] = []): Evaluation {
  const mapping = record.mapping ?? record.analysis.mapping;
  const withAck: Mapping = {
    ...mapping,
    options: { ...mapping.options, acknowledge: [...new Set([...mapping.options.acknowledge, ...acknowledge])] },
  };
  const translation = translate(record.files, withAck, knownPrefixes());
  const reconciled = reconcile(translation.model, withAck.options);
  try {
    const result = applyCommands(reconciled.commands as never, { dryRun: true, acknowledge: withAck.options.acknowledge, supernetStep: true });
    return { mapping: withAck, translation, reconciled, plan: { ok: true, result } };
  } catch (error) {
    if (error instanceof Problem) return { mapping: withAck, translation, reconciled, plan: { ok: false, problem: error } };
    throw error;
  }
}

// ---------------------------------------------------------------------------------
// Credentials

export type CredentialGate =
  | { allowed: true }
  | { allowed: false; reason: "forbidden" | "step_up_required" | "pin_coupling"; required: string | null; detail: string; accounts?: string };

/** Whether the signed-in account may store operator secrets now (IAM-07): an administrator with more than a PIN. */
export function credentialGate(principal: Principal): CredentialGate {
  if (!isAdmin(principal.user)) {
    return {
      allowed: false,
      reason: "forbidden",
      required: null,
      detail:
        "this account may not store or reveal operator secrets; leave the credential columns out or ask an administrator",
    };
  }
  if (STRENGTH_RANK[principal.session.strength] < STRENGTH_RANK.password) {
    return {
      allowed: false,
      reason: "step_up_required",
      required: "password",
      detail:
        "storing operator secrets needs a session of at least `password` (IAM-07); sign in with a stronger method or leave the credential columns out",
    };
  }
  // IAM-07: another account that may reveal secrets signs in with a PIN alone.
  if (mockSecrets.pinOnlyAccounts.length > 0) {
    const accounts = mockSecrets.pinOnlyAccounts.join(",");
    return {
      allowed: false,
      reason: "pin_coupling",
      required: null,
      accounts,
      detail: `the vault takes operator secrets only when every account that may reveal them has more than a PIN: ${accounts} sign in with a PIN alone`,
    };
  }
  return { allowed: true };
}

/** The digest of a credential (the mock vault keeps nothing else), to tell a changed one from one that is stored already. */
export function credentialDigest(login: string | null, password: string | null): string {
  return testDigest(JSON.stringify([login, password]));
}

function credentialCounts(ev: Evaluation): { new: number; changed: number; unchanged: number } {
  const counts = { new: 0, changed: 0, unchanged: 0 };
  const vault = vaultDigests();
  for (const op of ev.reconciled.credentials) {
    const value = ev.translation.credentials.get(op.host);
    if (!value) continue;
    const stored = vault.get(op.host);
    if (stored === undefined) counts.new += 1;
    else if (stored === credentialDigest(value.login, value.password)) counts.unchanged += 1;
    else counts.changed += 1;
  }
  return counts;
}

function credentialStatement(hosts: number, counts: { new: number; changed: number; unchanged: number }, policy: string): string {
  if (hosts === 0) return "The file has no login or password columns with values.";
  const who = hosts === 1 ? "1 host has" : `${hosts} hosts have`;
  if (policy === "skip") {
    return `${who} a login or password in the file. They are left out of this import and not stored anywhere.`;
  }
  return (
    `${who} a login or password in the file. They are not imported as IPAM fields: each host's login and password are stored ` +
    `encrypted in the vault as one operator secret attached to the host (${counts.new} new, ${counts.changed} replaced, ` +
    `${counts.unchanged} already stored). Revealing a secret is audited, exports never include them, and once the vault ` +
    `holds operator secrets a PIN alone no longer signs in to an account that can reveal them.`
  );
}

// ---------------------------------------------------------------------------------
// The preview

const ACTION_ORDER: readonly ItemAction[] = ["create", "update", "unchanged", "kept"];

function kindOf(key: ItemKey): string {
  return key.kind;
}

function summaryLines(counts: ReadonlyMap<string, number>, order: readonly [string, ItemAction][]): string[] {
  const lines: string[] = [];
  for (const [kind, action] of order) {
    if (action === "unchanged") continue;
    const count = counts.get(`${kind}|${action}`) ?? 0;
    const noun =
      count === 1 ? kind : kind === "address" ? "addresses" : kind === "prefix" ? "prefixes" : `${kind}s`;
    const verb =
      action === "create" ? "created" : action === "update" ? "updated" : "kept as stored (conflict)";
    lines.push(`${count} ${noun} ${verb}`);
  }
  return lines.length > 0 ? lines : ["no changes"];
}

function groupLoss(entries: readonly LossEntry[]): { loss: S["SheetLoss"][]; counts: S["LossCounts"] } {
  const counts = { info: 0, warning: 0, error: 0 };
  const groups: S["SheetLoss"][] = [];
  for (const entry of entries) {
    const severity = severityOf(entry.code);
    counts[severity] += 1;
    const item: S["LossItem"] = {
      ...(entry.location.row !== undefined ? { row: entry.location.row } : {}),
      ...(entry.location.column !== undefined ? { column: entry.location.column } : {}),
      code: entry.code,
      severity,
      detail: entry.detail,
    };
    const sheet = entry.location.sheet ?? null;
    const group = groups.find((g) => (g.sheet ?? null) === sheet);
    if (group) group.entries.push(item);
    else groups.push({ ...(sheet !== null ? { sheet } : {}), entries: [item] });
  }
  for (const group of groups) {
    group.entries.sort((a, b) => {
      const ra = a.row ?? -1;
      const rb = b.row ?? -1;
      if (ra !== rb) return ra - rb;
      return (a.column ?? "") < (b.column ?? "") ? -1 : (a.column ?? "") > (b.column ?? "") ? 1 : 0;
    });
  }
  return { loss: groups, counts };
}

export function planProblem(problem: Problem): S["PlanProblem"] {
  const body = problem.reply.body;
  return { code: body.code, status: body.status, detail: body.detail, params: { ...body.params } };
}

/** The preview of an import (`GET /imports/{id}/preview`): nothing is written. */
export function buildPreview(record: ImportRecord, ev: Evaluation, limit: number, gate: CredentialGate): ImportPreview {
  const { translation, reconciled, mapping } = ev;
  const actions = new Map<string, ItemAction>(reconciled.outcomes.map((o: ItemOutcome) => [itemId(o.key), o.action]));

  // Credentials.
  const hosts = translation.model.credentials.length;
  const credentialsOn = mapping.options.credentials === "import" && hosts > 0;
  const counts = credentialsOn ? credentialCounts(ev) : { new: 0, changed: 0, unchanged: 0 };
  const blocked = credentialsOn && !gate.allowed;

  // Counts per kind and action.
  const tally = new Map<string, number>();
  const add = (kind: string, action: ItemAction, n = 1): void => {
    tally.set(`${kind}|${action}`, (tally.get(`${kind}|${action}`) ?? 0) + n);
  };
  for (const outcome of reconciled.outcomes) add(kindOf(outcome.key), outcome.action);
  if (credentialsOn) {
    if (counts.new > 0) add("credential", "create", counts.new);
    if (counts.changed > 0) add("credential", "update", counts.changed);
    if (counts.unchanged > 0) add("credential", "unchanged", counts.unchanged);
  }
  const ordered: [string, ItemAction][] = [...tally.keys()]
    .map((k) => k.split("|") as [string, ItemAction])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : ACTION_ORDER.indexOf(a[1]) - ACTION_ORDER.indexOf(b[1])));

  // Rows.
  const rowCounts = { total: 0, free: 0, imported: 0, skipped: 0 };
  for (const row of translation.rows) {
    rowCounts.total += 1;
    rowCounts[row.status] += 1;
  }
  const rows: S["PreviewRow"][] = translation.rows.slice(0, limit).map((row) => ({
    location: {
      ...(row.location.sheet !== undefined ? { sheet: row.location.sheet } : {}),
      ...(row.location.row !== undefined ? { row: row.location.row } : {}),
    },
    status: row.status,
    items: row.items.map((key) => ({
      key,
      action: key.kind === "credential" ? (credentialsOn ? "create" : "kept") : (actions.get(itemId(key)) ?? "unchanged"),
    })),
  }));

  // The loss report: translation and reconcile issues, by sheet.
  const { loss, counts: lossCounts } = groupLoss([...translation.loss, ...reconciled.issues]);

  // The plan and what stops an apply.
  const blockers: string[] = [];
  let warnings: S["PlanWarning"][] = [];
  let planSummary: S["PlanSummary"] | undefined;
  let planError: S["PlanProblem"] | undefined;
  if (ev.plan.ok) {
    const plan = ev.plan.result.plan;
    planSummary = plan.summary;
    // The supernet step names how many imported networks lie inside.
    warnings = plan.warnings.map((w) => {
      const networks = w.code === "ipam.prefix.becomes_supernet" && w.object ? reconciled.supernetSteps.get(w.object.id) : undefined;
      return networks === undefined ? w : { ...w, params: { ...w.params, networks: String(networks) } };
    });
    if (plan.summary.unacknowledged.length > 0) blockers.push("ipam.plan.unacknowledged");
  } else {
    planError = planProblem(ev.plan.problem);
    blockers.push(planError.code);
  }
  if (reconciled.blocked) blockers.push(LOSS.conflictKept);
  if (blocked) blockers.push(PROBLEM.vaultRequired);

  return {
    id: record.id,
    base_revision: db.revision,
    summary: {
      counts: ordered.map(([kind, action]) => ({ kind, action, count: tally.get(`${kind}|${action}`) ?? 0 })),
      lines: summaryLines(tally, ordered),
      rows: rowCounts,
      loss: lossCounts,
      ...(planSummary ? { plan: planSummary } : {}),
      chunks: 1,
    },
    sheets: translation.sheets,
    rows,
    total_rows: rowCounts.total,
    loss,
    proposals: translation.proposals.map((p) => ({
      cidr: formatCidr(p.cidr),
      ...(p.vrf !== null ? { vrf: p.vrf } : {}),
      addresses: p.addresses.map(formatIp),
      accepted: p.accepted,
      origin: p.origin,
    })),
    credentials: {
      hosts,
      new: counts.new,
      changed: counts.changed,
      unchanged: counts.unchanged,
      statement: credentialStatement(hosts, counts, mapping.options.credentials),
      allowed: !blocked,
      // The machine code in `reason`, the English text in `detail` (as the server sends them).
      ...(blocked && !gate.allowed ? { reason: gate.reason, detail: gate.detail } : {}),
    },
    warnings,
    ...(planError ? { plan_error: planError } : {}),
    can_apply: blockers.length === 0,
    blockers,
  };
}
