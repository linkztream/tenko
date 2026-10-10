// VLAN provisioning and the prefixes of a VLAN in the mock API (docs/topology.md section 8,
// crates/tenko-ipam/src/vlan/provision.rs, WP2.7).
//
// `POST /vlans/provision?dry_run=true` answers the preview: the IPAM plan (the VLAN and the
// prefix as `planned`, planned by the IPAM mock with a dry run), the network the controller
// should have with the read-back diff, the steps of the job and the warnings to acknowledge.
// Without `dry_run` it computes the preview again, refuses while a warning that needs an
// acknowledgement is not acknowledged, writes the intent, puts the network on the mock
// controller and starts the job `ipam.vlan.provision`. `GET /vlans/{id}/prefixes` lists the
// prefixes linked to a VLAN.
//
// The one network controller is `mockVlanController` (topology-store.ts): tests switch it to
// read-only (`writes_enabled = false`), disable it or remove it (`present = false`).
//
// Simplifications: the job runs at once. The VLAN and the prefix become `active` when the job
// succeeds: at submit for an automatic or unchanged network step, when a person completes the
// manual task otherwise (a cancelled or failed job soft-deletes what it created).
import type { HttpHandler } from "msw";
import { bitsOf, formatIp, parseIp } from "../../ipam/ip";
import type { components } from "../generated/schema";
import type { ObjectRef, PlanView, PlanWarning, Prefix } from "../types";
import { requireSession } from "./auth";
import { db, onMockReset, subscribeEvents } from "./db";
import { applyCommands, ipamState } from "./ipam/api";
import { cidrOf } from "./ipam/net";
import { badPathId, invalidQuery, notFound, objectDeleted, planUnacknowledged } from "./ipam/problems";
import { Query } from "./ipam/query";
import { createJob, findJob, type MockStepInput } from "./job-store";
import { Problem, Reply, fail, fieldError, ok } from "./reply";
import { route } from "./route";
import { controllerInfo, mockVlanController } from "./topology-store";
import { isUuid, iso, randomId } from "./util";

export { mockVlanController };

type S = components["schemas"];
type ControllerInfo = S["ControllerInfo"];
type ControllerMode = S["ControllerMode"];
type ControllerPreview = S["ControllerPreview"];
type DiffEntry = S["DiffEntry"];
type NetworkSpec = S["NetworkSpec"];
type PrefixTarget = S["PrefixTarget"];
type VlanProvisionPreview = S["VlanProvisionPreview"];
type VlanProvisionSubmitted = S["VlanProvisionSubmitted"];
type VlanStepPreview = S["VlanStepPreview"];
type VlanTarget = S["VlanTarget"];
type ManualTask = S["ManualTask"];

/** Job kind, title and step kinds of a provision (crates/tenko-ipam/src/vlan). */
export const PROVISION_JOB = "ipam.vlan.provision";
export const PROVISION_TITLE = "ipam.vlan.job.title";
export const PROVISION_STEP = {
  intent: "ipam.vlan.intent",
  controller: "ipam.vlan.controller",
  manual: "ipam.vlan.manual",
  activate: "ipam.vlan.activate",
} as const;
export const PROVISION_TASK = "ipam.vlan.task.network";
/** Longest job with an automatic network step and with a manual one, in seconds. */
const AUTOMATIC_TIMEOUT_SECS = 3_600;
const MANUAL_TIMEOUT_SECS = 30 * 24 * 3_600;
/** Provision jobs through one controller that run at once. */
const CONTROLLER_PARALLELISM = 4;
const MAX_RELAYS = 8;
const MAX_NETWORK_NAME = 64;

// ---------------------------------------------------------------------------------
// The request

interface NewVlan {
  vid: number;
  name: string;
  site: string | null;
  vni: number | null;
  description: string | null;
  tags: string[];
}

interface NewPrefix {
  cidr: string;
  vrf: string | null;
  description: string | null;
}

interface Request {
  vlan: string | null;
  create: NewVlan | null;
  prefix: NewPrefix | null;
  connector: string | null;
  manual: boolean;
  network_name: string | null;
  dhcp_relay: string[];
  acknowledge: string[];
}

function malformed(detail: string): never {
  return fail("sys.invalid_request", { detail: `the request body is not valid: ${detail}` });
}

/** An object whose members are all in `allowed` (the server refuses unknown members). */
function objectOf(value: unknown, name: string, allowed: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return malformed(`\`${name}\` must be an object`);
  const out = value as Record<string, unknown>;
  for (const key of Object.keys(out)) {
    if (!allowed.includes(key)) return malformed(`unknown field \`${key}\` in \`${name}\`, expected one of ${allowed.join(", ")}`);
  }
  return out;
}

const present = (value: unknown): boolean => value !== undefined && value !== null;

function textOf(value: unknown, name: string): string | null {
  if (!present(value)) return null;
  if (typeof value !== "string") return malformed(`\`${name}\` must be a text`);
  return value;
}

function uuidOf(value: unknown, name: string): string | null {
  const text = textOf(value, name);
  if (text === null) return null;
  if (!isUuid(text)) return malformed(`\`${name}\` must be an identifier`);
  return text.toLowerCase();
}

function integerOf(value: unknown, name: string, max: number): number | null {
  if (!present(value)) return null;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > max) {
    return malformed(`\`${name}\` must be a whole number from 0 to ${max}`);
  }
  return value;
}

function listOf(value: unknown, name: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) return malformed(`\`${name}\` must be a list of texts`);
  return value as string[];
}

/** A network as `192.0.2.0/24`: the address in its canonical form, the length required. */
function cidrText(value: unknown, name: string): string {
  const text = textOf(value, name);
  const parts = (text ?? "").trim().split("/");
  const ip = parts.length === 2 ? parseIp(parts[0] ?? "") : null;
  const length = /^\d{1,3}$/.test(parts[1] ?? "") ? Number(parts[1]) : Number.NaN;
  if (!ip || !(length >= 0 && length <= bitsOf(ip.version))) return malformed(`\`${name}\` must be a network such as 192.0.2.0/24`);
  return `${formatIp(ip)}/${length}`;
}

function readRequest(raw: Record<string, unknown>): Request {
  const body = objectOf(raw, "body", ["acknowledge", "connector", "create", "dhcp_relay", "manual", "network_name", "prefix", "vlan"]);
  let create: NewVlan | null = null;
  if (present(body.create)) {
    const c = objectOf(body.create, "create", ["description", "name", "site", "tags", "vid", "vni"]);
    const vid = integerOf(c.vid, "create.vid", 65_535);
    const name = textOf(c.name, "create.name");
    if (vid === null || name === null) return malformed("`create` needs `vid` and `name`");
    create = {
      vid,
      name,
      site: uuidOf(c.site, "create.site"),
      vni: integerOf(c.vni, "create.vni", 4_294_967_295),
      description: textOf(c.description, "create.description"),
      tags: listOf(c.tags, "create.tags"),
    };
  }
  let prefix: NewPrefix | null = null;
  if (present(body.prefix)) {
    const p = objectOf(body.prefix, "prefix", ["cidr", "description", "vrf"]);
    prefix = {
      cidr: cidrText(p.cidr, "prefix.cidr"),
      vrf: uuidOf(p.vrf, "prefix.vrf"),
      description: textOf(p.description, "prefix.description"),
    };
  }
  if (present(body.manual) && typeof body.manual !== "boolean") return malformed("`manual` must be true or false");
  return {
    vlan: uuidOf(body.vlan, "vlan"),
    create,
    prefix,
    connector: uuidOf(body.connector, "connector"),
    manual: body.manual === true,
    network_name: textOf(body.network_name, "network_name"),
    dhcp_relay: listOf(body.dhcp_relay, "dhcp_relay").map((ip) => {
      const parsed = parseIp(ip.trim());
      return parsed ? formatIp(parsed) : malformed("`dhcp_relay` must list IP addresses");
    }),
    acknowledge: listOf(body.acknowledge, "acknowledge"),
  };
}

/** `ipam.vlan.invalid_request` (400): neither or both of `vlan` and `create`, a bad network name, too many relays. */
function invalid(detail: string, field: string): Problem {
  return new Problem("ipam.vlan.invalid_request", {
    status: 400,
    detail,
    params: { field },
    errors: [fieldError(field, "ipam.vlan.invalid_request")],
  });
}

function validate(request: Request): void {
  if (request.vlan !== null && request.create !== null) {
    throw invalid("name either an existing VLAN (`vlan`) or a new one (`create`), not both", "vlan");
  }
  if (request.vlan === null && request.create === null) {
    throw invalid("name an existing VLAN (`vlan`) or a new one (`create`)", "create");
  }
  if (request.network_name !== null) {
    const length = [...request.network_name.trim()].length;
    if (length === 0 || length > MAX_NETWORK_NAME) {
      throw invalid(`the network name must have 1 to ${MAX_NETWORK_NAME} characters`, "network_name");
    }
  }
  if (request.dhcp_relay.length > MAX_RELAYS) throw invalid(`at most ${MAX_RELAYS} DHCP relay targets`, "dhcp_relay");
  if (request.manual && request.connector !== null) throw invalid("a manual network step names no connector", "connector");
}

/** The request in a canonical form, to tell a repeated request from another one under the same key. */
function fingerprint(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(fingerprint).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const members = Object.entries(value).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${members.map(([name, member]) => `${JSON.stringify(name)}:${fingerprint(member)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

// ---------------------------------------------------------------------------------
// The network controller

function warning(code: string, message: string, vlan: string, params: Record<string, string>, request: Request): PlanWarning {
  return {
    code,
    message,
    object: { kind: "vlan", id: vlan },
    params,
    requires_ack: true,
    acknowledged: request.acknowledge.includes(code),
  };
}

/** The controller's plan for a network: refuses the management VLAN, diffs against what it has. */
function planNetwork(spec: NetworkSpec): DiffEntry[] {
  const networks = mockVlanController.networks;
  if (networks.some((n) => n.management === true && n.vlan === spec.vid)) {
    throw new Problem("connect.guardrail.protected_vlan", { status: 409, detail: `VLAN ${spec.vid} is the management network` });
  }
  const path = (field: string): string => `networks/vlan-${spec.vid}/${field}`;
  const have = networks.find((n) => n.vlan === spec.vid);
  if (!have) {
    return [
      { path: path("name"), after: spec.name },
      { path: path("vlan"), after: String(spec.vid) },
    ];
  }
  return have.name !== spec.name ? [{ path: path("name"), before: have.name, after: spec.name }] : [];
}

interface Resolved {
  preview: ControllerPreview;
  warnings: PlanWarning[];
  /** The controller of an automatic or unchanged network step. */
  connector: ControllerInfo | null;
}

/** The controller of the network step: the one the request names, else the only enabled one. */
function resolveController(request: Request, spec: NetworkSpec, vlan: string): Resolved {
  const listed = mockVlanController.present ? [controllerInfo()] : [];
  const enabled = listed.filter((c) => c.enabled);
  const manual = (reason: string, candidates: ControllerInfo[]): Resolved => ({
    preview: { mode: "manual", reason, network: spec, ...(candidates.length > 0 ? { candidates } : {}) },
    warnings: [],
    connector: null,
  });
  if (request.manual) return manual("ipam.vlan.manual_requested", enabled);
  let chosen: ControllerInfo | undefined;
  if (request.connector !== null) {
    chosen = listed.find((c) => c.id === request.connector);
    if (!chosen) {
      throw new Problem("ipam.vlan.controller_unknown", {
        status: 404,
        detail: `connector ${request.connector} is not a network controller of this server`,
        params: { connector: request.connector },
        errors: [fieldError("connector", "ipam.vlan.controller_unknown")],
      });
    }
    if (!chosen.enabled) {
      throw new Problem("ipam.vlan.controller_disabled", {
        status: 409,
        detail: `connector ${chosen.name} is disabled`,
        params: { connector: request.connector },
        errors: [fieldError("connector", "ipam.vlan.controller_disabled")],
      });
    }
  } else {
    chosen = enabled[0];
    if (!chosen) return manual("ipam.vlan.no_controller", []);
  }

  const diff = planNetwork(spec);
  const warnings: PlanWarning[] = [];
  let mode: ControllerMode;
  if (diff.length === 0) {
    mode = "unchanged";
  } else if (!chosen.writes_enabled) {
    warnings.push(
      warning(
        "ipam.vlan.controller_read_only",
        `connector ${chosen.name} does not allow writes (TGL-20); the network step is left to a person`,
        vlan,
        { connector: chosen.name },
        request,
      ),
    );
    mode = "manual";
  } else {
    mode = "automatic";
  }
  if (mode === "automatic" && diff.some((line) => line.before != null)) {
    warnings.push(
      warning(
        "ipam.vlan.network_changes",
        `the controller has a network on VLAN ${spec.vid} already; the write changes it`,
        vlan,
        { vid: String(spec.vid) },
        request,
      ),
    );
  }
  const preview: ControllerPreview = {
    mode,
    connector: chosen,
    network: spec,
    read_at: iso(Date.now()),
    ...(mode === "manual" ? { reason: "ipam.vlan.controller_read_only" } : {}),
    ...(diff.length > 0 ? { diff } : {}),
    ...(enabled.length > 0 ? { candidates: enabled } : {}),
  };
  return { preview, warnings, connector: mode === "manual" ? null : chosen };
}

// ---------------------------------------------------------------------------------
// The preview

interface JobStep {
  kind: string;
  task: ManualTask | null;
}

interface Computed {
  preview: VlanProvisionPreview;
  /** The IPAM commands of the intent step. */
  commands: { op: string; args: Record<string, unknown> }[];
  vlan: { id: string; created: boolean };
  prefix: string | null;
  steps: JobStep[];
  args: Record<string, string>;
  connector: ControllerInfo | null;
  spec: NetworkSpec;
}

const describe = (target: VlanTarget): string =>
  target.existing ? `the link to VLAN ${target.vid} (${target.name})` : `VLAN ${target.vid} (${target.name})`;

/** The VLAN of a request: the existing one it names, or the one it creates (as planned). */
function targetOf(request: Request): VlanTarget {
  if (request.vlan !== null) {
    const vlan = ipamState().data.vlan.get(request.vlan);
    if (!vlan) throw notFound("vlan", request.vlan);
    if (vlan.meta.deleted) throw objectDeleted("vlan", vlan.id);
    return {
      id: vlan.id,
      vid: vlan.vid,
      name: vlan.name,
      existing: true,
      status: vlan.status,
      ...(vlan.site ? { site: vlan.site } : {}),
    };
  }
  const create = request.create as NewVlan;
  return {
    id: randomId(),
    vid: create.vid,
    name: create.name.trim(),
    existing: false,
    status: "planned",
    ...(create.site ? { site: create.site } : {}),
  };
}

function compute(request: Request): Computed {
  validate(request);
  const target = targetOf(request);
  const create = request.create;
  const prefixId = request.prefix ? randomId() : null;
  const commands: Computed["commands"] = [];
  if (create) {
    commands.push({
      op: "create_vlan",
      args: {
        id: target.id,
        vid: create.vid,
        name: create.name,
        status: "planned",
        ...(create.site ? { site: create.site } : {}),
        ...(create.vni !== null ? { vni: create.vni } : {}),
        ...(create.description !== null ? { description: create.description } : {}),
        ...(create.tags.length > 0 ? { tags: create.tags } : {}),
      },
    });
  }
  if (request.prefix && prefixId) {
    commands.push({
      op: "create_prefix",
      args: {
        id: prefixId,
        cidr: request.prefix.cidr,
        role: "network",
        status: "planned",
        vlan: target.id,
        ...(request.prefix.vrf ? { vrf: request.prefix.vrf } : {}),
        ...(target.site ? { site: target.site } : {}),
        ...(request.prefix.description !== null ? { description: request.prefix.description } : {}),
      },
    });
  }
  let plan: PlanView | null = null;
  if (commands.length > 0) {
    plan = applyCommands(commands as never, { dryRun: true, acknowledge: request.acknowledge }).plan;
  }
  const spec: NetworkSpec = {
    vid: target.vid,
    name: request.network_name !== null ? request.network_name.trim() : target.name,
    ...(request.dhcp_relay.length > 0 ? { dhcp_relay: request.dhcp_relay } : {}),
  };
  const resolved = resolveController(request, spec, target.id);

  const args: Record<string, string> = { vid: String(target.vid), name: spec.name };
  if (request.prefix) args.cidr = request.prefix.cidr;
  const taskArgs = { ...args, ...(resolved.preview.connector ? { connector: resolved.preview.connector.name } : {}) };
  const intent = commands.length > 0;
  const steps: JobStep[] = [];
  const previews: VlanStepPreview[] = [];
  const add = (kind: string, stepKind: string, automatic: boolean, text: string, params: Record<string, string>, task: ManualTask | null) => {
    steps.push({ kind: stepKind, task });
    previews.push({ kind, step_kind: stepKind, automatic, text, params: { ...params } });
  };
  if (intent) {
    add(
      "ipam.intent",
      PROVISION_STEP.intent,
      true,
      request.prefix
        ? `Create ${describe(target)} and the network ${request.prefix.cidr} in IPAM as planned`
        : `Create VLAN ${target.vid} (${target.name}) in IPAM as planned`,
      taskArgs,
      null,
    );
  }
  if (resolved.preview.mode === "manual") {
    const task: ManualTask = { instruction: PROVISION_TASK, args: { ...taskArgs } };
    add(
      "l2.manual",
      PROVISION_STEP.manual,
      false,
      `Create the network ${spec.name} on VLAN ${spec.vid} on the switches and access points`,
      taskArgs,
      task,
    );
  } else {
    add(
      "l2.network",
      PROVISION_STEP.controller,
      true,
      `Create the network ${spec.name} on VLAN ${spec.vid} through ${resolved.preview.connector?.name ?? "the network controller"}: dry run, write, read back and compare`,
      taskArgs,
      null,
    );
  }
  if (intent) add("activate", PROVISION_STEP.activate, true, `Set VLAN ${target.vid} and its network active`, taskArgs, null);

  const warnings: PlanWarning[] = [...(plan?.warnings ?? []), ...resolved.warnings];
  const unacknowledged = [...new Set(warnings.filter((w) => w.requires_ack === true && w.acknowledged !== true).map((w) => w.code))].sort();
  const prefixTarget: PrefixTarget | null =
    request.prefix && prefixId ? { id: prefixId, cidr: request.prefix.cidr, ...(request.prefix.vrf ? { vrf: request.prefix.vrf } : {}) } : null;
  return {
    preview: {
      vlan: target,
      ...(prefixTarget ? { prefix: prefixTarget } : {}),
      ...(plan ? { plan } : {}),
      controller: resolved.preview,
      steps: previews,
      ...(warnings.length > 0 ? { warnings } : {}),
      ...(unacknowledged.length > 0 ? { unacknowledged } : {}),
      base_revision: db.revision,
    },
    commands,
    vlan: { id: target.id, created: create !== null },
    prefix: prefixId,
    steps,
    args,
    connector: resolved.connector,
    spec,
  };
}

// ---------------------------------------------------------------------------------
// The job

/** What the job of a provision created, until the job ends. */
interface Created {
  vlan: string | null;
  prefix: string | null;
}

const settling = new Map<string, Created>();

/** Applies commands that follow the job (the activation, the compensation); a refusal is left to a person. */
function follow(commands: { op: string; args: Record<string, unknown> }[]): void {
  try {
    applyCommands(commands as never);
  } catch (error) {
    if (!(error instanceof Problem)) throw error;
  }
}

/** Activates what a succeeded job created and soft-deletes what a failed or cancelled one created. */
function settle(jobId: string): void {
  const created = settling.get(jobId);
  if (!created) return;
  const state = findJob(jobId)?.job.state;
  const update = (kind: "vlan" | "prefix", id: string) => ({
    op: kind === "vlan" ? "update_vlan" : "update_prefix",
    args: { id, expected: null, patch: { status: "active" } },
  });
  const remove = (kind: "vlan" | "prefix", id: string) => ({ op: "delete", args: { object: { kind, id }, expected: null, cascade: false } });
  if (state === "succeeded") {
    settling.delete(jobId);
    const commands = [];
    if (created.vlan) commands.push(update("vlan", created.vlan));
    if (created.prefix) commands.push(update("prefix", created.prefix));
    follow(commands);
  } else if (state === "cancelled" || state === "rolled_back" || state === "failed") {
    settling.delete(jobId);
    if (created.prefix) follow([remove("prefix", created.prefix)]);
    if (created.vlan) follow([remove("vlan", created.vlan)]);
  }
}

// The manual task is completed (or the job cancelled) through the jobs API: look at the jobs
// that wait for it when the jobs topic announces a change.
subscribeEvents((event) => {
  if (event.topic !== "jobs") return;
  for (const id of [...settling.keys()]) settle(id);
});

/** Puts the network on the mock controller: renames the one the VLAN has, or adds one. */
function writeNetwork(spec: NetworkSpec): void {
  const have = mockVlanController.networks.find((n) => n.vlan === spec.vid);
  if (have) have.name = spec.name;
  else mockVlanController.networks.push({ id: `net-${randomId().slice(0, 8)}`, name: spec.name, vlan: spec.vid, management: false });
}

function jobSteps(computed: Computed, changes: ObjectRef[]): MockStepInput[] {
  return computed.steps.map((step): MockStepInput => {
    if (step.task) return { kind: step.kind, automatic: false, manual: step.task, changes };
    return { kind: step.kind, automatic: true, summary: `ipam.vlan.step.${step.kind.slice("ipam.vlan.".length)}`, args: computed.args, changes };
  });
}

function startJob(computed: Computed): string {
  const changes: ObjectRef[] = [{ kind: "vlan", id: computed.vlan.id }];
  if (computed.prefix) changes.push({ kind: "prefix", id: computed.prefix });
  const targets = [...changes];
  if (computed.connector) targets.push({ kind: "connector", id: computed.connector.id });
  const manual = computed.steps.some((s) => s.kind === PROVISION_STEP.manual);
  const intent = computed.commands.length > 0;
  const jobId = createJob(
    {
      kind: PROVISION_JOB,
      title: PROVISION_TITLE,
      targets,
      ...(computed.connector ? { group: `${PROVISION_JOB}.${computed.connector.id}`, groupLimit: CONTROLLER_PARALLELISM } : {}),
      timeoutSecs: manual ? MANUAL_TIMEOUT_SECS : AUTOMATIC_TIMEOUT_SECS,
      steps: jobSteps(computed, changes),
    },
    // The intent step ran at submit: it is done when the job starts.
    { startedSteps: intent ? 1 : 0 },
  );
  if (intent) {
    settling.set(jobId, { vlan: computed.vlan.created ? computed.vlan.id : null, prefix: computed.prefix });
    settle(jobId);
  }
  return jobId;
}

// ---------------------------------------------------------------------------------
// Routes

const receipts = new Map<string, { fingerprint: string; submitted: VlanProvisionSubmitted }>();

onMockReset(() => {
  receipts.clear();
  settling.clear();
});

function dryRunOf(url: URL): boolean {
  const query = new Query(url, ["dry_run", "limit", "cursor", "at_least"]);
  const value = query.one("dry_run")?.trim().toLowerCase() ?? "";
  if (value === "") return false;
  if (["true", "1", "yes"].includes(value)) return true;
  if (["false", "0", "no"].includes(value)) return false;
  throw invalidQuery("dry_run", value, "expected true or false");
}

const provision = route("post", "/api/v1/vlans/provision", async (ctx) => {
  requireSession();
  const request = readRequest((await ctx.body()) as Record<string, unknown>);
  const dryRun = dryRunOf(ctx.url);
  if (dryRun) return ok(compute(request).preview);

  const key = ctx.header("idempotency-key");
  const print = fingerprint(request);
  if (key) {
    const earlier = receipts.get(key);
    if (earlier) {
      if (earlier.fingerprint !== print) {
        throw new Problem("ipam.idempotency_mismatch", {
          status: 422,
          detail: "the idempotency key was used before for a different provision",
        });
      }
      return new Reply(202, { ...earlier.submitted, replayed: true });
    }
  }
  const computed = compute(request);
  if (computed.preview.unacknowledged && computed.preview.unacknowledged.length > 0) {
    throw planUnacknowledged(computed.preview.unacknowledged);
  }
  // The intent step, then the network on the controller, then the job that records both.
  if (computed.commands.length > 0) applyCommands(computed.commands as never, { acknowledge: request.acknowledge });
  if (computed.preview.controller.mode === "automatic") writeNetwork(computed.spec);
  const submitted: VlanProvisionSubmitted = {
    job_id: startJob(computed),
    vlan: computed.vlan.id,
    ...(computed.prefix ? { prefix: computed.prefix } : {}),
    preview: computed.preview,
    replayed: false,
  };
  if (key) receipts.set(key, { fingerprint: print, submitted });
  return new Reply(202, submitted);
});

/** Orders prefixes by VRF, then by network (IPv4 first, the shorter prefix first). */
function comparePrefixes(a: Prefix, b: Prefix): number {
  if (a.vrf !== b.vrf) return a.vrf < b.vrf ? -1 : 1;
  const x = cidrOf(a.cidr);
  const y = cidrOf(b.cidr);
  if (x.version !== y.version) return x.version - y.version;
  if (x.network !== y.network) return x.network < y.network ? -1 : 1;
  return x.length - y.length;
}

const vlanPrefixes = route("get", "/api/v1/vlans/{id}/prefixes", (ctx) => {
  requireSession();
  const id = ctx.params.id;
  if (!isUuid(id)) throw badPathId(id);
  const query = new Query(ctx.url, ["deleted", "limit", "cursor", "at_least"]);
  const deleted = query.one("deleted");
  if (deleted !== null && deleted !== "exclude" && deleted !== "include") {
    throw invalidQuery("deleted", deleted, `\`${deleted}\` is not \`exclude\` or \`include\``);
  }
  const limit = query.one("limit");
  if (limit !== null && !(/^\d+$/.test(limit) && Number(limit) >= 1 && Number(limit) <= 1000)) {
    throw invalidQuery("limit", limit, "limit must be a whole number from 1 to 1000");
  }
  const data = ipamState().data;
  const vlan = data.vlan.get(id.toLowerCase());
  if (!vlan) throw notFound("vlan", id.toLowerCase());
  const items = [...data.prefix.values()]
    .filter((p) => p.vlan === vlan.id && (deleted === "include" || !p.meta.deleted))
    .sort(comparePrefixes)
    .map((p) => structuredClone(p));
  return ok({ items, next_cursor: null, revision: db.revision });
});

export const vlanRoutes: HttpHandler[] = [provision, vlanPrefixes];
