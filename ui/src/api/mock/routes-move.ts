// The move API of the mock (IPAM-19, WP1.4b, WP2.8): POST /api/v1/moves with `?dry_run=true`
// answers the preview, without it the IPAM intent changes and one job per object starts, all
// in one group. It follows the generated Move* types (src/api/moves.ts) and the decisions
// of 2026-10-09: the same host part when it is free, else the next free address; steps by
// mode. Every item has its two times (`timing`): the next DHCP activity and the migration
// deadline, from the request, the short lease, the client's lease in the mock lease table,
// the longest lease of the target's pools plus a margin, else 3,600 s, never below 300 s; the
// longest deadline is the move's timeout. A client with a lease starts with `dhcp.prepare` and
// waits for its renewal with the short lease (`dhcp.short_lease`, a manual step) unless the
// request has `move_now`. The L2 step of each device comes from the mock network
// controller (move-l2.ts): through the controller (`l2.controller`), by a person (`l2.move`,
// with the reason), or none; a refusal of a guardrail is a warning to acknowledge, and a
// submit with `expect_fingerprint` runs the confirmed plan or answers 409
// `ipam.move.plan_changed`.
import { http, type HttpHandler } from "msw";
import type { MoveItem, MovePreview, MoveStepPreview, MoveSubmitted, MoveTimeoutSource, MoveTiming } from "../moves";
import type { Address, AssignmentMode, Host, Interface, ObjectRef, PlanWarning } from "../types";
import { cidrOf, compareIp, formatIp, hostPart, parseCidr, parseIp, usableRange, withHostPart, addToIp, containsIp } from "../../ipam/ip";
import { requireSession } from "./auth";
import { applyCommands, ipamState, longestLeaseSecs } from "./ipam/api";
import { createJob, MOVE_STEP, moveSteps, type MockStepInput } from "./job-store";
import { decideL2, fingerprintOf, L2_CODES, l2Args, l2Step } from "./move-l2";
import { dhcpLeaseState } from "./routes-dhcp-leases";
import { Problem } from "./reply";
import { randomId } from "./util";

const MIN_TIMEOUT = 300;
const MAX_TIMEOUT = 604_800;
const DEFAULT_TIMEOUT = 3600;

interface Planned {
  item: MoveItem;
  address: Address;
}

const replays = new Map<string, { body: string; answer: MoveSubmitted }>();

function problem(code: string, status: number, detail: string, params: Record<string, string> = {}): never {
  throw new Problem(code, { status, detail, params });
}

function readRequest(raw: unknown) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) problem("sys.invalid_request", 400, "the body must be a JSON object");
  const body = raw as Record<string, unknown>;
  for (const key of Object.keys(body)) {
    if (!["objects", "target", "timeout_secs", "parallelism", "acknowledge", "expect_fingerprint", "move_now"].includes(key)) {
      problem("sys.invalid_request", 400, `unknown member ${key}`);
    }
  }
  const objects = Array.isArray(body.objects) ? body.objects : [];
  const refs: ObjectRef[] = objects.map((o) => {
    const r = o as Partial<ObjectRef>;
    if (!r || (r.kind !== "host" && r.kind !== "address") || typeof r.id !== "string") {
      return problem("ipam.validation", 400, "objects must name hosts or addresses");
    }
    return { kind: r.kind, id: r.id };
  });
  if (refs.length === 0) problem("ipam.validation", 400, "no objects to move");
  if (typeof body.target !== "string") problem("ipam.validation", 400, "target is required");
  const timeout = typeof body.timeout_secs === "number" ? body.timeout_secs : null;
  if (timeout !== null && (timeout < MIN_TIMEOUT || timeout > MAX_TIMEOUT)) {
    problem("ipam.validation", 400, `timeout_secs must be between ${MIN_TIMEOUT} and ${MAX_TIMEOUT}`);
  }
  const parallelism = typeof body.parallelism === "number" ? Math.max(1, Math.min(32, Math.floor(body.parallelism))) : 2;
  const acknowledge = Array.isArray(body.acknowledge) ? body.acknowledge.filter((c): c is string => typeof c === "string") : [];
  const expectFingerprint = typeof body.expect_fingerprint === "string" ? body.expect_fingerprint : null;
  const moveNow = body.move_now === true;
  if (body.move_now !== undefined && typeof body.move_now !== "boolean") problem("ipam.validation", 400, "move_now must be true or false");
  return { refs, target: body.target, timeout, parallelism, acknowledge, expectFingerprint, moveNow };
}

// ---------------------------------------------------------------------------------
// The two times of an item and the preparation (crates/tenko-ipam/src/moves/timing.rs, lease.rs)

/** The short lease a renewal gets, the margin after a lease, and the longest wait for a renewal. */
const SHORT_LEASE_SECS = 120;
const MARGIN_SECS = 60;
const PREPARE_LIMIT_SECS = 3600;

/** The client's active lease on its old address in the mock lease table, when Tenko holds one. */
function heldLease(mac: string | null | undefined, ip: string, now: number) {
  if (!mac) return undefined;
  return dhcpLeaseState().leases.find(
    (l) => l.family === "v4" && l.addr === ip && l.state === "active" && l.mac?.toLowerCase() === mac.toLowerCase() && Date.parse(l.ends) > now,
  );
}

/** The next DHCP message of a client with a lease: T1 (half), then T2 (seven eighths), then the end. */
function nextActivityOf(start: number, end: number, now: number): number {
  const secs = end - start;
  const t1 = start + secs / 2;
  const t2 = start + (secs * 7) / 8;
  return now <= t1 ? t1 : now < t2 ? t2 : end;
}

/** The timing of one item: where its next DHCP activity comes from, the deadline, what the job does first. */
function timingOf(item: MoveItem, input: { now: number; moveNow: boolean; requestSecs: number | null; poolSecs: number | null }): MoveTiming {
  const { now, moveNow, requestSecs, poolSecs } = input;
  const iso = (ms: number) => new Date(ms).toISOString();
  const held = heldLease(item.mac, item.old_ip, now);
  const start = held ? Date.parse(held.cltt) : 0;
  const end = held ? Date.parse(held.ends) : 0;
  const next = held ? nextActivityOf(start, end, now) : null;
  let prepare: MoveTiming["prepare"];
  if (!item.mac) prepare = "no_mac";
  else if (!held || next === null) prepare = "not_served";
  else if (moveNow) prepare = "move_now";
  else prepare = end - start <= SHORT_LEASE_SECS * 1000 || (next - now) / 1000 <= PREPARE_LIMIT_SECS ? "short_lease" : "limit";

  let deadline: number;
  let source: MoveTimeoutSource;
  if (requestSecs !== null) [deadline, source] = [requestSecs, "request"];
  else if (prepare === "short_lease") [deadline, source] = [SHORT_LEASE_SECS + MARGIN_SECS, "short_lease"];
  else if (held) [deadline, source] = [Math.ceil((end - now) / 1000) + MARGIN_SECS, "lease"];
  else if (poolSecs) [deadline, source] = [poolSecs + MARGIN_SECS, "pool"];
  else [deadline, source] = [DEFAULT_TIMEOUT, "default"];

  const timing: MoveTiming = {
    next_activity_source: held ? "lease" : poolSecs ? "pool" : "unknown",
    prepare,
    deadline_secs: Math.min(MAX_TIMEOUT, Math.max(MIN_TIMEOUT, deadline)),
    deadline_source: source,
  };
  if (held && next !== null) {
    timing.next_activity = iso(next);
    timing.lease_start = held.cltt;
    timing.lease_end = held.ends;
    if (!moveNow) timing.short_lease_secs = SHORT_LEASE_SECS;
  } else if (poolSecs) {
    timing.next_activity = iso(now + (poolSecs / 2) * 1000);
  }
  return timing;
}

function interfaceOf(address: Address): { iface: Interface | null; host: Host | null } {
  const data = ipamState().data;
  const iface = address.interface ? (data.interface.get(address.interface) ?? null) : null;
  return { iface, host: iface ? (data.host.get(iface.host) ?? null) : null };
}

/** The addresses an object of the request moves: the host's addresses of the target family. */
function addressesOf(ref: ObjectRef, version: 4 | 6): Address[] {
  const data = ipamState().data;
  if (ref.kind === "address") {
    const a = data.address.get(ref.id);
    if (!a || a.meta.deleted) problem("ipam.not_found", 404, `address ${ref.id} not found`, { kind: "address", id: ref.id });
    return [a];
  }
  const host = data.host.get(ref.id);
  if (!host || host.meta.deleted) problem("ipam.not_found", 404, `host ${ref.id} not found`, { kind: "host", id: ref.id });
  const ifaces = new Set([...data.interface.values()].filter((i) => i.host === host.id && !i.meta.deleted).map((i) => i.id));
  return [...data.address.values()].filter(
    (a) => !a.meta.deleted && a.interface && ifaces.has(a.interface) && parseIp(a.ip)?.version === version,
  );
}

/** The step kind of the job for each kind of the preview (crates/tenko-ipam/src/moves/preview.rs). */
const STEP_KIND: Readonly<Record<string, string>> = {
  "ipam.intent": MOVE_STEP.intent,
  "dhcp.prepare": MOVE_STEP.prepare,
  "dhcp.short_lease": MOVE_STEP.lease,
  "dhcp.manual": MOVE_STEP.dhcp,
  "dns.manual": MOVE_STEP.dns,
  "device.manual": MOVE_STEP.device,
  "l2.move": MOVE_STEP.l2,
  "l2.controller": MOVE_STEP.controller,
  observe: MOVE_STEP.observe,
  cleanup: MOVE_STEP.cleanup,
};

/** The steps of one item in the order of the server: intent, DHCP, DNS, device, layer 2, observation, cleanup. */
function steps(mode: AssignmentMode | null, hasName: boolean): { kind: string; automatic: boolean }[] {
  const out = [{ kind: "ipam.intent", automatic: true }];
  if (mode === "reserved") out.push({ kind: "dhcp.manual", automatic: false });
  if (hasName) out.push({ kind: "dns.manual", automatic: false });
  if (mode === "static") out.push({ kind: "device.manual", automatic: false });
  out.push({ kind: "l2.move", automatic: false }, { kind: "observe", automatic: false }, { kind: "cleanup", automatic: true });
  return out;
}

function plan(raw: unknown): { preview: MovePreview; planned: Planned[]; request: ReturnType<typeof readRequest> } {
  const request = readRequest(raw);
  const data = ipamState().data;
  const prefix = data.prefix.get(request.target);
  if (!prefix || prefix.meta.deleted) {
    return problem("ipam.not_found", 404, `prefix ${request.target} not found`, { kind: "prefix", id: request.target });
  }
  if (prefix.role !== "network") problem("ipam.move.target_supernet", 422, `${prefix.cidr} is a supernet`, { cidr: prefix.cidr });
  const target = cidrOf(parseIp(prefix.cidr.split("/")[0] ?? "") ?? { version: 4, value: 0n }, Number(prefix.cidr.split("/")[1]));
  const ranges = [...data.range.values()].filter((r) => r.prefix === prefix.id && !r.meta.deleted);
  const used = new Set(
    [...data.address.values()].filter((a) => !a.meta.deleted && a.vrf === prefix.vrf).map((a) => a.ip),
  );
  const inRange = (ip: string) => {
    const v = parseIp(ip);
    if (!v) return false;
    return ranges.some((r) => {
      const first = parseIp(r.first);
      const last = parseIp(r.last);
      return !!first && !!last && compareIp(first, v) <= 0 && compareIp(v, last) <= 0;
    });
  };
  const usable = usableRange(target);
  const taken = new Set<string>();
  const free = (ip: string) => !used.has(ip) && !taken.has(ip) && !inRange(ip);

  const planned: Planned[] = [];
  for (const ref of request.refs) {
    const addresses = addressesOf(ref, target.version);
    for (const address of addresses) {
      const { iface, host } = interfaceOf(address);
      if (host?.mode === "unmanaged") problem("ipam.move.unmanaged", 422, `${host.name} is unmanaged`, { host: host.name });
      if (host?.lock) problem("ipam.host.locked", 423, `${host.name} is locked`, { host: host.name });
      const old = parseIp(address.ip);
      const oldPrefix = data.prefix.get(address.prefix);
      const oldCidr = oldPrefix ? parseCidr(oldPrefix.cidr) : null;
      const offset = old && oldCidr ? hostPart(oldCidr, old) : null;
      const same = offset !== null ? withHostPart(target, offset) : null;
      let newIp: string | null = null;
      let reason: string | null = null;
      if (same && compareIp(same, usable.first) >= 0 && compareIp(same, usable.last) <= 0) {
        const text = formatIp(same);
        if (free(text)) newIp = text;
        else reason = used.has(text) || taken.has(text) ? "ipam.move.host_part_taken" : "ipam.move.host_part_reserved";
      } else reason = "ipam.move.host_part_outside";
      if (newIp === null) {
        let cur: ReturnType<typeof addToIp> = usable.first;
        while (cur && containsIp(target, cur) && compareIp(cur, usable.last) <= 0) {
          const text = formatIp(cur);
          if (free(text)) {
            newIp = text;
            break;
          }
          cur = addToIp(cur, 1n);
        }
      }
      if (newIp === null) problem("ipam.address.full", 409, `no free address in ${prefix.cidr}`, { cidr: prefix.cidr });
      taken.add(newIp);
      const name = address.dns_name ?? null;
      const warnings: PlanWarning[] = [];
      if (host?.mode === "reserved" && !iface?.mac) {
        warnings.push({
          code: "ipam.host.reservation_identifier",
          message: `${host.name} is reserved but has no MAC address`,
          params: { host: host.name },
        });
      }
      // The arguments the server attaches to every step (crates/tenko-ipam/src/moves/preview.rs).
      const stepParams = (): Record<string, string> => {
        const out: Record<string, string> = {
          prefix: prefix.id,
          cidr: prefix.cidr,
          vrf: prefix.vrf,
          old_ip: address.ip,
          new_ip: newIp as string,
          address: address.id,
          new_address: address.id,
        };
        const targetVlan = prefix.vlan ? data.vlan.get(prefix.vlan) : undefined;
        if (targetVlan) {
          out.vlan = targetVlan.id;
          out.vid = String(targetVlan.vid);
        }
        if (host) out.host = host.name;
        if (iface?.mac) out.mac = iface.mac;
        return out;
      };
      const stepList: MoveStepPreview[] = steps(host?.mode ?? null, !!name).map((s) => ({
        kind: s.kind,
        step_kind: STEP_KIND[s.kind] ?? s.kind,
        automatic: s.automatic,
        text: `move.step.${s.kind.replace(".", "_")}`,
        params: stepParams(),
      }));
      planned.push({
        address,
        item: {
          object: { kind: "address", id: address.id },
          requested: ref,
          host: host?.id ?? null,
          host_name: host?.name ?? null,
          mode: host?.mode ?? null,
          interface: iface?.id ?? null,
          mac: iface?.mac ?? null,
          old_ip: address.ip,
          new_ip: newIp,
          new_address: address.id,
          same_host_part: reason === null,
          reason,
          dns: name ? { name, old: address.ip, new: newIp } : null,
          steps: stepList,
          warnings,
        },
      });
    }
  }

  const lease = longestLeaseSecs(prefix.id);
  const now = Date.now();
  for (const p of planned) {
    p.item.timing = timingOf(p.item, { now, moveNow: request.moveNow, requestSecs: request.timeout, poolSecs: lease });
  }
  // The longest deadline of the items, and how it was chosen.
  let timeout = 0;
  let source: MoveTimeoutSource = "default";
  for (const { item } of planned) {
    const timing = item.timing as MoveTiming;
    if (timing.deadline_secs > timeout) [timeout, source] = [timing.deadline_secs, timing.deadline_source];
  }
  const vlan = prefix.vlan ? data.vlan.get(prefix.vlan) : undefined;
  const targetView: MovePreview["target"] = {
    prefix: prefix.id,
    cidr: prefix.cidr,
    vrf: prefix.vrf,
    vlan: prefix.vlan ?? null,
    vid: vlan?.vid ?? null,
    lease_secs: lease,
  };

  // The L2 step of every device, then its steps in the order of the server.
  const l2 = decideL2(
    planned.map((p) => p.item),
    targetView,
  );
  planned.forEach((p, index) => {
    const decided = l2.items[index];
    if (!decided) return;
    p.item.l2 = decided;
    p.item.steps = p.item.steps.flatMap((step): MoveStepPreview[] => {
      if (step.kind !== "l2.move") return [step];
      if (decided.action === "unchanged" || decided.action === "shared") return [];
      const args = { ...step.params, ...l2Args(decided) };
      if (decided.action === "port_profile" || decided.action === "client_vlan") {
        return [{ kind: "l2.controller", step_kind: MOVE_STEP.controller, automatic: true, text: "move.step.l2_controller", params: args }];
      }
      return [{ ...step, params: args }];
    });
    p.item.warnings = [...(p.item.warnings ?? []), ...l2.warnings.filter((w) => w.object?.id === p.item.object.id)];
  });
  // The DHCP preparation: a client Tenko serves is marked as moving first; unless the operator
  // moves at once, a manual step waits for its renewal with the short lease right before the
  // network change. (The server also prepares a client of an enabled target scope; the mock
  // does so for clients with a lease only.)
  for (const p of planned) {
    const timing = p.item.timing as MoveTiming;
    if (!["short_lease", "limit", "move_now"].includes(timing.prepare)) continue;
    const base = p.item.steps[0]?.params ?? {};
    const prepare: MoveStepPreview = {
      kind: "dhcp.prepare",
      step_kind: MOVE_STEP.prepare,
      automatic: true,
      text: "move.step.dhcp_prepare",
      params: base,
    };
    const steps = [prepare, ...p.item.steps];
    if (timing.prepare === "short_lease" && timing.next_activity) {
      const wait: MoveStepPreview = {
        kind: "dhcp.short_lease",
        step_kind: MOVE_STEP.lease,
        automatic: false,
        text: "move.step.dhcp_short_lease",
        params: { ...base, short_secs: String(timing.short_lease_secs ?? SHORT_LEASE_SECS), next_activity: timing.next_activity },
      };
      const at = steps.findIndex((s) => s.kind === "l2.move" || s.kind === "l2.controller" || s.kind === "observe");
      steps.splice(at < 0 ? steps.length : at, 0, wait);
    }
    p.item.steps = steps;
  }
  const warnings: PlanWarning[] = l2.warnings.map((w) => ({ ...w, acknowledged: request.acknowledge.includes(w.code) }));
  const unacknowledged = [...new Set(warnings.filter((w) => w.requires_ack && !w.acknowledged).map((w) => w.code))];
  const items = planned.map((p) => p.item);
  return {
    request,
    planned,
    preview: {
      target: targetView,
      timeout_secs: timeout,
      timeout_source: source,
      move_now: request.moveNow,
      parallelism: request.parallelism,
      base_revision: 0,
      items,
      warnings,
      unacknowledged,
      controllers: l2.controllers,
      // "Move now" is part of the plan, so a preview made without it is not the one confirmed with it.
      fingerprint: fingerprintOf(items, request.moveNow ? `${prefix.id}#now` : prefix.id),
    },
  };
}

/** The steps of the job of one item, with the arguments of the server (see moveSteps in job-store.ts). */
function jobSteps(item: MoveItem, target: MovePreview["target"], timeoutSecs: number): MockStepInput[] {
  const changes: ObjectRef[] = [item.object];
  if (item.host) changes.push({ kind: "host", id: item.host });
  return moveSteps(
    {
      prefix: target.prefix,
      cidr: target.cidr,
      vrf: target.vrf,
      oldIp: item.old_ip,
      newIp: item.new_ip,
      address: item.object.id,
      newAddress: item.new_address ?? item.object.id,
      vlan: target.vlan ?? null,
      vid: target.vid ?? null,
      host: item.host_name ?? null,
      mac: item.mac ?? null,
      dnsName: item.dns?.name ?? null,
      mode: item.mode ?? null,
      timeoutSecs,
      l2: l2Step(item),
      prepare: item.steps.some((s) => s.kind === "dhcp.prepare"),
      shortLease:
        item.steps.some((s) => s.kind === "dhcp.short_lease") && item.timing?.next_activity
          ? { secs: item.timing.short_lease_secs ?? SHORT_LEASE_SECS, nextActivity: item.timing.next_activity }
          : undefined,
    },
    { changes },
  );
}

const moves = http.post("/api/v1/moves", async ({ request }) => {
  try {
    requireSession();
    const url = new URL(request.url);
    const text = await request.text();
    let raw: unknown;
    try {
      raw = text ? JSON.parse(text) : undefined;
    } catch {
      return problem("sys.invalid_request", 400, "the request body is not valid JSON");
    }
    const dryRun = url.searchParams.get("dry_run") === "true";
    const key = request.headers.get("idempotency-key");
    if (!dryRun && key) {
      const earlier = replays.get(key);
      if (earlier) {
        if (earlier.body !== text) return problem("ipam.idempotency_mismatch", 422, "the key was used for another request");
        return Response.json({ ...earlier.answer, replayed: true }, { status: 202 });
      }
    }
    const { preview, planned, request: req } = plan(raw);
    if (dryRun) return Response.json(preview, { status: 200 });
    if (req.expectFingerprint !== null && req.expectFingerprint !== preview.fingerprint) {
      return problem(L2_CODES.planChanged, 409, "the move would now do something else than the confirmed preview; preview it again", {
        fingerprint: preview.fingerprint ?? "",
      });
    }
    if ((preview.unacknowledged ?? []).length > 0) {
      const codes = (preview.unacknowledged ?? []).join(",");
      return problem("ipam.plan.unacknowledged", 409, `the move needs an acknowledgement of: ${codes}`, { codes });
    }

    // The IPAM intent of every object, as one change, then one job per object.
    applyCommands(
      planned.map((p) => ({ op: "update_address", args: { id: p.address.id, expected: null, patch: { ip: p.item.new_ip } } })) as never,
      { acknowledge: req.acknowledge },
    );
    // The server names the group "ipam.move." and the 32 hex digits of a UUID.
    const group = `ipam.move.${randomId().replace(/-/g, "")}`;
    const jobs = planned.map((p) => ({
      object: p.item.requested,
      job_id: createJob(
        {
          kind: "ipam.move",
          title: "ipam.move.title",
          // The moved address, its host when it has one, and the target network.
          targets: [
            p.item.object,
            ...(p.item.host ? [{ kind: "host" as const, id: p.item.host }] : []),
            { kind: "prefix" as const, id: preview.target.prefix },
            ...((p.item.l2?.action === "port_profile" || p.item.l2?.action === "client_vlan") && p.item.l2.connector
              ? [{ kind: "connector" as const, id: p.item.l2.connector.id }]
              : []),
          ],
          group,
          groupLimit: req.parallelism,
          timeoutSecs: preview.timeout_secs,
          steps: jobSteps(p.item, preview.target, p.item.timing?.deadline_secs ?? preview.timeout_secs),
        },
        { startedSteps: 1 },
      ),
    }));
    const answer: MoveSubmitted = {
      group,
      jobs,
      items: preview.items,
      timeout_secs: preview.timeout_secs,
      parallelism: req.parallelism,
      warnings: preview.warnings,
      replayed: false,
    };
    if (key) replays.set(key, { body: text, answer });
    return Response.json(answer, { status: 202 });
  } catch (error) {
    if (error instanceof Problem) return error.reply.toResponse();
    throw error;
  }
});

export const moveRoutes: HttpHandler[] = [moves];
