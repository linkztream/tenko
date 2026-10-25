// Observations, proposals and adoption policies of the mock API (docs/reconciliation.md):
// the facts list and the picture of one subject across sources, the proposals with their
// decisions (approve plans and applies the suggested commands through the IPAM planner,
// reject records the reason, a run now expires what no longer holds), and the adoption
// policy of a prefix with its inheritance from the containing prefixes of the VRF.
//
// Simplifications: the facts and proposals are seeded (reconcile-store.ts) instead of being
// derived by rules; a run only expires open proposals whose difference intent has caught up
// with; every signed-in account may read, and administrators and operators may decide.
import type { HttpHandler } from "msw";
import { containsCidr, containsIp, parseCidr, parseIp } from "../../ipam/ip";
import type { components } from "../generated/schema";
import { appendAudit, principalNow } from "./audit-store";
import { requireSession, type Principal } from "./auth";
import { db, isAdmin, recordEvent } from "./db";
import { parseMac } from "./import-shape";
import { applyCommands, ipamState } from "./ipam/api";
import { notFound, objectDeleted } from "./ipam/problems";
import { checkRemember, chooseName, rememberChoice, type ApproveRequest } from "./name-authority";
import { Problem, ok } from "./reply";
import { paginate, route } from "./route";
import { REASON_GONE, RECONCILER, reconcileState, type AdoptionPolicy, type IntentProposal, type ObservedFact } from "./reconcile-store";
import { isUuid } from "./util";

type S = components["schemas"];

// ---------------------------------------------------------------------------------
// Shared checks

function invalidQuery(name: string, detail: string): Problem {
  return new Problem("sys.invalid_query", { status: 400, detail: `query parameter \`${name}\`: ${detail}`, params: { parameter: name } });
}

/** Refuses a query parameter that is not in `allowed`. */
function onlyQuery(url: URL, allowed: readonly string[]): void {
  for (const name of url.searchParams.keys()) {
    if (!allowed.includes(name)) throw invalidQuery(name, "unknown parameter");
  }
}

/** The values of a filter that may repeat or be comma-separated, checked against `known`. */
function listParam<T extends string>(url: URL, name: string, known: readonly T[]): T[] | null {
  const values = url.searchParams
    .getAll(name)
    .flatMap((v) => v.split(","))
    .map((v) => v.trim())
    .filter(Boolean);
  if (values.length === 0) return null;
  for (const value of values) {
    if (!known.includes(value as T)) throw invalidQuery(name, `\`${value}\` is not one of ${known.join(", ")}`);
  }
  return values as T[];
}

function requireId(id: string): void {
  if (!isUuid(id)) {
    throw new Problem("sys.invalid_request", { status: 400, detail: `\`${id}\` is not a valid identifier`, params: { part: "path" } });
  }
}

/** Administrators and operators decide proposals; viewers and auditors read them. */
function requireDecider(principal: Principal): void {
  if (!principal.user.roles.some((role) => role === "admin" || role === "operator")) {
    throw new Problem("auth.forbidden", { status: 403, detail: "deciding proposals needs the admin or operator role" });
  }
}

/** A sort parameter: comma-separated fields, `-` in front for descending. */
function sortOf(url: URL, fields: readonly string[], fallback: string): { field: string; desc: boolean }[] {
  const raw = url.searchParams.get("sort") ?? fallback;
  return raw
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const desc = part.startsWith("-");
      const field = desc ? part.slice(1) : part;
      if (!fields.includes(field)) throw invalidQuery("sort", `\`${field}\` is not one of ${fields.join(", ")}`);
      return { field, desc };
    });
}

function compareBy<T>(keys: { field: string; desc: boolean }[], value: (item: T, field: string) => string | number): (a: T, b: T) => number {
  return (a, b) => {
    for (const { field, desc } of keys) {
      const x = value(a, field);
      const y = value(b, field);
      const order = x < y ? -1 : x > y ? 1 : 0;
      if (order !== 0) return desc ? -order : order;
    }
    return 0;
  };
}

// ---------------------------------------------------------------------------------
// Facts

const FACT_TYPES = ["host", "address", "attachment", "services", "os", "link", "name", "vendor"] as const;

function isCurrent(fact: ObservedFact, now = Date.now()): boolean {
  return !fact.expires_at || Date.parse(fact.expires_at) > now;
}

/** The MAC addresses a fact names. */
function macsOf(fact: ObservedFact): string[] {
  const o = fact.observed;
  switch (o.type) {
    case "host":
      return o.data.macs ?? [];
    case "address":
      return o.data.mac ? [o.data.mac] : [];
    case "attachment":
    case "vendor":
      return [o.data.mac];
    default:
      return [];
  }
}

/** The IP addresses a fact names. */
function ipsOf(fact: ObservedFact): string[] {
  const o = fact.observed;
  switch (o.type) {
    case "host":
      return o.data.ips ?? [];
    case "address":
    case "services":
    case "os":
    case "name":
      return [o.data.ip];
    default:
      return [];
  }
}

/** The name a fact gives its subject: an inventory host's name, or the name a probe found for an address. */
function nameOf(fact: ObservedFact): string | null {
  const o = fact.observed;
  return o.type === "host" ? (o.data.name ?? null) : o.type === "name" ? o.data.name : null;
}

/**
 * Whether a fact is a sighting of what it names. A name or a vendor says what a thing is called
 * or who made it, not that it is in use, so intent's last sightings leave such facts out
 * (docs/reconciliation.md section 2.6, docs/scanning.md section 3.3).
 */
function isSighting(fact: ObservedFact): boolean {
  return fact.observed.type !== "name" && fact.observed.type !== "vendor";
}

/** The text `q` searches: subject key, name, OS, platform, parent, tags and attachment device. */
function searchText(fact: ObservedFact): string {
  const o = fact.observed;
  const parts = [fact.subject_key];
  if (o.type === "host") parts.push(o.data.name ?? "", o.data.os ?? "", o.data.platform ?? "", o.data.parent ?? "", ...(o.data.tags ?? []));
  if (o.type === "attachment") parts.push(o.data.device);
  if (o.type === "os") parts.push(o.data.guess);
  if (o.type === "name") parts.push(o.data.name);
  if (o.type === "vendor") parts.push(o.data.vendor);
  return parts.join(" ").toLowerCase();
}

function connectorOf(source: S["ObservationSource"]): string | null {
  return source.type === "inventory" || source.type === "network_controller" ? source.connector : null;
}

const observations = route("get", "/api/v1/observations", (ctx) => {
  requireSession();
  const url = ctx.url;
  onlyQuery(url, ["limit", "cursor", "at_least", "source", "type", "mac", "ip", "within", "q", "current", "sort"]);
  let facts = [...reconcileState().facts];
  const source = url.searchParams.get("source");
  if (source) facts = facts.filter((f) => f.source_key === source || connectorOf(f.source) === source);
  const type = url.searchParams.get("type");
  if (type !== null) {
    if (!FACT_TYPES.includes(type as (typeof FACT_TYPES)[number])) throw invalidQuery("type", `must be one of ${FACT_TYPES.join(", ")}`);
    facts = facts.filter((f) => f.subject.type === type);
  }
  const macText = url.searchParams.get("mac");
  if (macText !== null) {
    const mac = parseMac(macText);
    if (!mac) throw invalidQuery("mac", "is not a MAC address");
    facts = facts.filter((f) => macsOf(f).includes(mac));
  }
  const ipText = url.searchParams.get("ip");
  if (ipText !== null) {
    const ip = parseIp(ipText);
    if (!ip) throw invalidQuery("ip", "is not an IP address");
    facts = facts.filter((f) => ipsOf(f).some((x) => parseIp(x)?.value === ip.value && parseIp(x)?.version === ip.version));
  }
  const within = url.searchParams.get("within");
  if (within !== null) {
    const net = parseCidr(within);
    if (!net) throw invalidQuery("within", "is not a network");
    facts = facts.filter((f) => ipsOf(f).some((x) => {
      const ip = parseIp(x);
      return !!ip && containsIp(net, ip);
    }));
  }
  const q = url.searchParams.get("q")?.trim().toLowerCase();
  if (q) facts = facts.filter((f) => searchText(f).includes(q));
  const current = url.searchParams.get("current");
  if (current !== null) {
    if (current !== "true" && current !== "false") throw invalidQuery("current", "must be true or false");
    facts = facts.filter((f) => isCurrent(f) === (current === "true"));
  }
  const keys = sortOf(url, ["last_seen", "first_seen", "source", "subject"], "-last_seen");
  facts.sort(
    compareBy<ObservedFact>(keys, (f, field) =>
      field === "source" ? f.source_key : field === "subject" ? f.subject_key : field === "first_seen" ? f.first_seen : f.last_seen,
    ),
  );
  return ok(paginate(facts, url, db.revision));
});

/** What a subject of `GET /observations/{subject}` asks for. */
function subjectOf(raw: string): { kind: "mac" | "ip" | "name"; value: string } {
  const text = raw.trim();
  // eslint-disable-next-line no-control-regex -- control characters are what this refuses
  if (!text || text.length > 253 || /[\u0000-\u001f\u007f]/.test(text)) {
    throw new Problem("ipam.validation", { status: 400, detail: "the subject is not a MAC address, an IP address or a name", params: { field: "subject" } });
  }
  const mac = parseMac(text);
  if (mac) return { kind: "mac", value: mac };
  const ip = parseIp(text);
  if (ip) return { kind: "ip", value: text };
  return { kind: "name", value: text.toLowerCase() };
}

function sameIp(a: string, b: string): boolean {
  const x = parseIp(a);
  const y = parseIp(b);
  return !!x && !!y && x.version === y.version && x.value === y.value;
}

const observation = route("get", "/api/v1/observations/{subject}", (ctx) => {
  requireSession();
  onlyQuery(ctx.url, ["at_least"]);
  const subject = subjectOf(decodeURIComponent(ctx.params.subject));
  const named = reconcileState().facts.filter((f) =>
    subject.kind === "mac"
      ? macsOf(f).includes(subject.value)
      : subject.kind === "ip"
        ? ipsOf(f).some((ip) => sameIp(ip, subject.value))
        : (nameOf(f) ?? "").toLowerCase() === subject.value,
  );
  if (named.length === 0) {
    throw new Problem("ipam.not_found", { status: 404, detail: `no source has observed ${subject.value}`, params: { kind: "observation", id: subject.value } });
  }
  const now = Date.now();
  const facts = [...named].sort((a, b) => Number(isCurrent(b, now)) - Number(isCurrent(a, now)) || (a.last_seen < b.last_seen ? 1 : a.last_seen > b.last_seen ? -1 : 0));
  const current = facts.filter((f) => isCurrent(f, now));
  const basis = current.length > 0 ? current : facts;
  const sorted = (values: Iterable<string>) => [...new Set(values)].sort();
  const attachments = basis.flatMap((f): S["AttachmentView"][] =>
    f.observed.type === "attachment"
      ? [{ device: f.observed.data.device, mac: f.observed.data.mac, port: f.observed.data.port ?? null, ssid: f.observed.data.ssid ?? null, vlan: f.observed.data.vlan ?? null, source: f.source_key, last_seen: f.last_seen }]
      : [],
  );
  const macs = sorted(basis.flatMap(macsOf));
  const ips = sorted(basis.flatMap(ipsOf));
  const names = sorted(basis.flatMap((f) => (nameOf(f) ? [nameOf(f)!] : [])));

  // The intent that matches: interfaces by MAC, addresses by IP, hosts by name and interfaces.
  const data = ipamState().data;
  const interfaces = [...data.interface.values()].filter((i) => !i.meta.deleted && !!i.mac && macs.includes(i.mac));
  const addresses = [...data.address.values()].filter((a) => !a.meta.deleted && ips.some((ip) => sameIp(ip, a.ip)));
  const hostIds = new Set(interfaces.map((i) => i.host));
  for (const host of data.host.values()) {
    if (!host.meta.deleted && names.includes(host.name.toLowerCase())) hostIds.add(host.id);
  }
  const latest = (match: (f: ObservedFact) => boolean): S["IntentSighting"] | null => {
    const f = current.filter((x) => isSighting(x) && match(x)).sort((a, b) => (a.last_seen < b.last_seen ? 1 : -1))[0];
    return f ? { at: f.last_seen, observation: f.observation, source: f.source_key } : null;
  };
  const sightings: S["ObjectSighting"][] = [
    ...addresses.flatMap((a) => {
      const s = latest((f) => ipsOf(f).some((ip) => sameIp(ip, a.ip)));
      return s ? [{ object: { kind: "address", id: a.id } as S["ObjectRef"], sighting: s }] : [];
    }),
    ...interfaces.flatMap((i) => {
      const s = latest((f) => macsOf(f).includes(i.mac!));
      return s ? [{ object: { kind: "interface", id: i.id } as S["ObjectRef"], sighting: s }] : [];
    }),
  ];
  const seen = basis.map((f) => [f.first_seen, f.last_seen] as const);
  const view: S["SubjectView"] = {
    subject: `${subject.kind}:${subject.value}`,
    facts,
    summary: {
      current: current.length > 0,
      sources: sorted(current.map((f) => f.source_key)),
      first_seen: seen.map(([first]) => first).sort()[0] ?? null,
      last_seen: seen.map(([, last]) => last).sort().at(-1) ?? null,
      macs,
      ips,
      names,
      os: sorted(basis.flatMap((f) => (f.observed.type === "host" && f.observed.data.os ? [f.observed.data.os] : f.observed.type === "os" ? [f.observed.data.guess] : []))),
      platforms: sorted(basis.flatMap((f) => (f.observed.type === "host" && f.observed.data.platform ? [f.observed.data.platform] : []))),
      parents: sorted(basis.flatMap((f) => (f.observed.type === "host" && f.observed.data.parent ? [f.observed.data.parent] : []))),
      open_tcp: [...new Set(basis.flatMap((f) => (f.observed.type === "services" ? f.observed.data.open_tcp : [])))].sort((a, b) => a - b),
      tls_tcp: [...new Set(basis.flatMap((f) => (f.observed.type === "services" ? (f.observed.data.tls_tcp ?? []) : [])))].sort((a, b) => a - b),
      vendors: sorted(basis.flatMap((f) => (f.observed.type === "vendor" ? [f.observed.data.vendor] : []))),
      attachments,
      tags: sorted(basis.flatMap((f) => (f.observed.type === "host" ? (f.observed.data.tags ?? []) : []))),
    },
    intent: {
      hosts: [...hostIds],
      interfaces: interfaces.map((i) => i.id),
      addresses: addresses.map((a) => a.id),
      vrfs: [...new Set(addresses.map((a) => a.vrf))],
    },
    sightings,
    revision: db.revision,
  };
  return ok(view);
});

// ---------------------------------------------------------------------------------
// Proposals

const KINDS = ["discovered_host", "orphaned_intent", "address_mismatch", "conflict", "outside_prefixes", "vlan_discovered", "prefix_vlan_mismatch", "host_name"] as const;
const STATES = ["open", "accepted", "rejected", "expired", "superseded"] as const;
const SEVERITIES = ["info", "warning", "critical"] as const;
const SEVERITY_RANK: Record<string, number> = { info: 0, warning: 1, critical: 2 };

function lastSeen(p: IntentProposal): string {
  return p.evidence.map((e) => e.last_seen).sort().at(-1) ?? "";
}

/** Whether a proposal is about a prefix: its own, an address or a network inside it, or an involved object. */
function aboutPrefix(p: IntentProposal, prefixId: string): boolean {
  if (p.subject.prefix === prefixId) return true;
  if ((p.subject.objects ?? []).some((o) => o.id === prefixId)) return true;
  const prefix = ipamState().data.prefix.get(prefixId);
  if (!prefix || (p.subject.vrf && p.subject.vrf !== prefix.vrf)) return false;
  const outer = parseCidr(prefix.cidr);
  if (!outer) return false;
  const ip = p.subject.ip ? parseIp(p.subject.ip) : null;
  if (ip && containsIp(outer, ip)) return true;
  const inner = p.subject.cidr ? parseCidr(p.subject.cidr) : null;
  return !!inner && containsCidr(outer, inner);
}

function aboutSubject(p: IntentProposal, text: string): boolean {
  const mac = parseMac(text);
  if (mac) return p.subject.mac === mac || p.evidence.some((e) => e.mac === mac);
  if (parseIp(text)) return (!!p.subject.ip && sameIp(p.subject.ip, text)) || p.evidence.some((e) => !!e.ip && sameIp(e.ip, text));
  if (isUuid(text)) return p.id === text || p.subject.prefix === text || (p.subject.objects ?? []).some((o) => o.id === text);
  const needle = text.toLowerCase();
  return (p.subject.name ?? "").toLowerCase().includes(needle) || p.key.toLowerCase().includes(needle);
}

const proposals = route("get", "/api/v1/proposals", (ctx) => {
  requireSession();
  const url = ctx.url;
  onlyQuery(url, ["limit", "cursor", "at_least", "kind", "state", "severity", "prefix", "subject", "sort"]);
  const kinds = listParam(url, "kind", KINDS);
  const states = listParam(url, "state", STATES);
  const severities = listParam(url, "severity", SEVERITIES);
  const prefix = url.searchParams.get("prefix");
  if (prefix !== null && !isUuid(prefix)) throw invalidQuery("prefix", "is not a prefix identifier");
  const subject = url.searchParams.get("subject")?.trim();
  const keys = sortOf(url, ["created", "updated", "severity", "kind", "state", "last_seen"], "-created");
  const items = [...reconcileState().proposals.values()]
    .filter((p) => !kinds || kinds.includes(p.kind))
    .filter((p) => !states || states.includes(p.state))
    .filter((p) => !severities || severities.includes(p.severity))
    .filter((p) => prefix === null || aboutPrefix(p, prefix))
    .filter((p) => !subject || aboutSubject(p, subject))
    .sort(
      compareBy<IntentProposal>(keys, (p, field) =>
        field === "severity"
          ? (SEVERITY_RANK[p.severity] ?? 0)
          : field === "kind"
            ? p.kind
            : field === "state"
              ? p.state
              : field === "updated"
                ? p.updated
                : field === "last_seen"
                  ? lastSeen(p)
                  : p.created,
      ),
    );
  return ok(paginate(items, url, db.revision));
});

function findProposal(id: string): IntentProposal {
  requireId(id);
  const found = reconcileState().proposals.get(id);
  if (!found) throw new Problem("ipam.proposal.not_found", { status: 404, detail: `proposal ${id} does not exist`, params: { id } });
  return found;
}

const etag = (revision: number | undefined) => ({ ETag: `"${revision ?? 0}"` });

const proposal = route("get", "/api/v1/proposals/{id}", (ctx) => {
  requireSession();
  onlyQuery(ctx.url, ["at_least"]);
  const found = findProposal(ctx.params.id);
  return ok(found, etag(found.revision));
});

/** The checks every decision makes: open, and at the revision the client read. */
function decidable(p: IntentProposal, ifMatch: number | "*" | null): void {
  if (ifMatch !== null && ifMatch !== "*" && ifMatch !== p.revision) {
    throw new Problem("ipam.proposal.revision_mismatch", {
      status: 412,
      detail: `proposal ${p.id} is at revision ${p.revision}, not ${ifMatch}`,
      params: { id: p.id, expected: String(ifMatch), actual: String(p.revision) },
    });
  }
  if (p.state !== "open") {
    throw new Problem("ipam.proposal.not_open", { status: 409, detail: `proposal ${p.id} is ${p.state} already`, params: { id: p.id, state: p.state } });
  }
}

/** Writes a changed proposal: a new revision and an `ipam` event that names it. */
function commit(p: IntentProposal): IntentProposal {
  const event = recordEvent("ipam", { objects: [{ kind: "proposal", id: p.id }], tables: ["ipam.proposals"] });
  const next = { ...p, revision: event.id ?? db.revision };
  reconcileState().proposals.set(p.id, next);
  return next;
}

/** The body of an approval, checked: `choice` is text, `remember` is `host` or `source`. */
function readApprove(body: Record<string, unknown>): ApproveRequest {
  for (const key of Object.keys(body)) {
    if (key !== "choice" && key !== "remember") {
      throw new Problem("sys.invalid_request", { status: 400, detail: `unknown field \`${key}\``, params: { part: "body" } });
    }
  }
  const { choice, remember } = body;
  if (choice !== undefined && choice !== null && typeof choice !== "string") {
    throw new Problem("sys.invalid_request", { status: 400, detail: "`choice` must be text", params: { part: "body" } });
  }
  if (remember !== undefined && remember !== null && remember !== "host" && remember !== "source") {
    throw new Problem("sys.invalid_request", { status: 400, detail: "`remember` must be `host` or `source`", params: { part: "body" } });
  }
  return { choice: (choice as string | null | undefined) ?? null, remember: (remember as ApproveRequest["remember"]) ?? null };
}

/** The commands with the host named `name`: the host a proposal creates or renames takes the chosen name. */
function namedCommands(commands: readonly S["IpamCommand"][], name: string): S["IpamCommand"][] {
  return commands.map((c) => {
    if (c.op === "create_host") return { ...c, args: { ...c.args, name } };
    if (c.op === "update_host") return { ...c, args: { ...c.args, patch: { ...c.args.patch, name } } };
    return c;
  });
}

/** Plans (a dry run) or applies the commands of an open proposal and marks it accepted. */
function approveOne(
  found: IntentProposal,
  ifMatch: number | "*" | null,
  dryRun: boolean,
  acknowledge: readonly string[],
  request: ApproveRequest = {},
): S["Decision"] {
  decidable(found, ifMatch);
  // A choice must be one of the names the proposal offers; the host takes the chosen name.
  const chosen = chooseName(found.choices ?? [], request);
  checkRemember(request, isAdmin(requireSession().user));
  const commands = chosen ? namedCommands(found.commands ?? [], chosen.name) : (found.commands ?? []);
  if (commands.length === 0) {
    throw new Problem("ipam.proposal.nothing_to_apply", {
      status: 409,
      detail: `proposal ${found.id} suggests no change; resolve its cause and reject it`,
      params: { id: found.id },
    });
  }
  const outcome = applyCommands(commands, { dryRun, acknowledge });
  if (dryRun) {
    return { dry_run: true, proposal: found, plan: outcome.plan, warnings: outcome.warnings, results: [], revision: null, job_id: null };
  }
  const renamed = commands.find((c) => c.op === "update_host");
  const hostId = outcome.results.find((r) => r.kind === "host")?.id ?? (renamed?.op === "update_host" ? renamed.args.id : undefined);
  rememberChoice(request, chosen, hostId && chosen ? { id: hostId, name: chosen.name } : null);
  const accepted = commit({
    ...found,
    state: "accepted",
    commands,
    decided: { at: new Date().toISOString(), by: principalNow() },
    results: outcome.results,
    updated: new Date().toISOString(),
  });
  appendAudit({ action: "ipam.proposal.approve", objects: [{ kind: "proposal", id: found.id }, ...outcome.results], context: { rule: found.rule } });
  return {
    dry_run: false,
    proposal: accepted,
    plan: outcome.plan,
    warnings: outcome.warnings,
    results: outcome.results,
    revision: accepted.revision ?? null,
    job_id: outcome.job_id,
  };
}

const approve = route("post", "/api/v1/proposals/{id}/approve", async (ctx) => {
  const principal = requireSession();
  onlyQuery(ctx.url, ["dry_run", "acknowledge"]);
  const found = findProposal(ctx.params.id);
  requireDecider(principal);
  const dryRun = ctx.query("dry_run") === "true";
  const acknowledge = (ctx.query("acknowledge") ?? "")
    .split(",")
    .map((c) => c.trim())
    .filter(Boolean);
  const request = readApprove(await ctx.optionalBody());
  const decision = approveOne(found, ctx.ifMatch(), dryRun, acknowledge, request);
  return ok(decision, etag(decision.proposal.revision));
});

/** The reason of a rejection as it is recorded: trimmed, empty for none; refused when too long. */
function cleanReason(raw: unknown): string {
  if (raw !== undefined && raw !== null && typeof raw !== "string") {
    throw new Problem("sys.invalid_request", { status: 400, detail: "reason must be text", params: { part: "body" } });
  }
  const reason = typeof raw === "string" ? raw.trim() : "";
  // eslint-disable-next-line no-control-regex -- control characters other than line breaks and tabs are refused
  if (new TextEncoder().encode(reason).length > 1024 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(reason)) {
    throw new Problem("ipam.validation", {
      status: 400,
      detail: "the reason has at most 1,024 bytes and no control characters other than line breaks and tabs",
      params: { field: "reason" },
    });
  }
  return reason;
}

/** Marks an open proposal rejected with the (already checked) reason. */
function rejectOne(found: IntentProposal, ifMatch: number | "*" | null, reason: string): S["Decision"] {
  decidable(found, ifMatch);
  const rejected = commit({
    ...found,
    state: "rejected",
    reason: reason || null,
    decided: { at: new Date().toISOString(), by: principalNow() },
    updated: new Date().toISOString(),
  });
  appendAudit({ action: "ipam.proposal.reject", objects: [{ kind: "proposal", id: found.id }], context: reason ? { reason } : {} });
  return { dry_run: false, proposal: rejected, results: [], warnings: [], revision: rejected.revision ?? null, job_id: null };
}

const reject = route("post", "/api/v1/proposals/{id}/reject", async (ctx) => {
  const principal = requireSession();
  onlyQuery(ctx.url, []);
  const found = findProposal(ctx.params.id);
  requireDecider(principal);
  const body = await ctx.optionalBody();
  const reason = cleanReason(body.reason);
  const decision = rejectOne(found, ctx.ifMatch(), reason);
  return ok(decision, etag(decision.proposal.revision));
});

/** The rules of the address conflicts that "keep both" decides. */
const KEEPABLE_RULES = ["ipam.reconcile.conflict_shared_address", "ipam.reconcile.conflict_address_taken"];

/** Keeps an address conflict as it is: the proposal is rejected, with the reason. */
const keep = route("post", "/api/v1/proposals/{id}/keep", async (ctx) => {
  const principal = requireSession();
  onlyQuery(ctx.url, []);
  const found = findProposal(ctx.params.id);
  requireDecider(principal);
  const body = await ctx.optionalBody();
  const reason = cleanReason(body.reason);
  decidable(found, ctx.ifMatch());
  if (!KEEPABLE_RULES.includes(found.rule)) {
    throw new Problem("ipam.proposal.not_keepable", {
      status: 409,
      detail: `proposal ${found.id} is not an address conflict`,
      params: { id: found.id, rule: found.rule },
    });
  }
  const kept = commit({
    ...found,
    state: "rejected",
    reason: reason || null,
    decided: { at: new Date().toISOString(), by: principalNow() },
    updated: new Date().toISOString(),
  });
  appendAudit({ action: "ipam.proposal.keep", objects: [{ kind: "proposal", id: found.id }], context: reason ? { reason } : {} });
  const decision: S["Decision"] = { dry_run: false, proposal: kept, results: [], warnings: [], revision: kept.revision ?? null, job_id: null };
  return ok(decision, etag(kept.revision));
});

/** The most proposals one batch takes (the server's limit). */
const MAX_BATCH = 500;

/** The identifiers of a batch body, checked as the server does; `reason` only where allowed. */
function batchIds(body: Record<string, unknown>, allowed: readonly string[]): string[] {
  for (const key of Object.keys(body)) {
    if (!allowed.includes(key)) {
      throw new Problem("sys.invalid_request", { status: 400, detail: `unknown field \`${key}\``, params: { part: "body" } });
    }
  }
  const ids = body.ids;
  if (!Array.isArray(ids) || !ids.every((id) => typeof id === "string" && isUuid(id))) {
    throw new Problem("sys.invalid_request", { status: 400, detail: "`ids` must be a list of proposal identifiers", params: { part: "body" } });
  }
  if (ids.length === 0) {
    throw new Problem("ipam.proposal.batch_empty", { status: 422, detail: "name at least one proposal" });
  }
  if (ids.length > MAX_BATCH) {
    throw new Problem("ipam.proposal.batch_too_large", {
      status: 422,
      detail: `${ids.length} proposals exceed the limit of ${MAX_BATCH} in one request`,
      params: { count: String(ids.length), limit: String(MAX_BATCH) },
    });
  }
  return ids as string[];
}

/** One id of a batch: the decision applied, or a skip with the refusal of the single route. */
function batchItem(id: string, done: "approved" | "rejected", decide: () => void): S["BatchItem"] {
  try {
    decide();
    return { id, outcome: done };
  } catch (err) {
    if (!(err instanceof Problem)) throw err;
    const { status, code, detail, params } = err.reply.body;
    return { id, outcome: "skipped", code, status, message: detail, ...(params && Object.keys(params).length ? { params } : {}) };
  }
}

/** The answer of a batch: the items and the counts. */
function batchDecision(results: S["BatchItem"][]): S["BatchDecision"] {
  const count = (outcome: S["BatchItem"]["outcome"]) => results.filter((r) => r.outcome === outcome).length;
  return { results, approved: count("approved"), rejected: count("rejected"), skipped: count("skipped") };
}

const approveMany = route("post", "/api/v1/proposals/approve", async (ctx) => {
  const principal = requireSession();
  onlyQuery(ctx.url, []);
  const body = await ctx.body();
  const ids = batchIds(body, ["ids", "choices"]);
  requireDecider(principal);
  // The choice of name per proposal; a proposal not named takes its proposed name.
  const choices = body.choices;
  if (choices !== undefined && (typeof choices !== "object" || choices === null || Array.isArray(choices))) {
    throw new Problem("sys.invalid_request", { status: 400, detail: "`choices` must be an object by proposal", params: { part: "body" } });
  }
  const requests = new Map(Object.entries((choices ?? {}) as Record<string, Record<string, unknown>>).map(([id, r]) => [id, readApprove(r)]));
  return ok(batchDecision(ids.map((id) => batchItem(id, "approved", () => void approveOne(findProposal(id), null, false, [], requests.get(id))))));
});

const rejectMany = route("post", "/api/v1/proposals/reject", async (ctx) => {
  const principal = requireSession();
  onlyQuery(ctx.url, []);
  const body = await ctx.body();
  const ids = batchIds(body, ["ids", "reason"]);
  const reason = cleanReason(body.reason);
  requireDecider(principal);
  return ok(batchDecision(ids.map((id) => batchItem(id, "rejected", () => void rejectOne(findProposal(id), null, reason)))));
});

/** Whether the difference behind an open proposal still exists in intent. */
function stillHolds(p: IntentProposal): boolean {
  const data = ipamState().data;
  const live = <T extends { meta: { deleted?: unknown } }>(m: Map<string, T>) => [...m.values()].filter((x) => !x.meta.deleted);
  switch (p.rule) {
    case "ipam.reconcile.discovered_mac":
      return !p.subject.mac || !live(data.interface).some((i) => i.mac === p.subject.mac);
    case "ipam.reconcile.discovered_address":
      return !p.subject.ip || !live(data.address).some((a) => a.vrf === p.subject.vrf && sameIp(a.ip, p.subject.ip!));
    case "ipam.reconcile.address_mismatch": {
      const address = (p.subject.objects ?? []).find((o) => o.kind === "address");
      const current = address ? data.address.get(address.id) : undefined;
      return !!current && !current.meta.deleted && !!p.subject.ip && !sameIp(current.ip, p.subject.ip);
    }
    case "ipam.reconcile.outside_prefixes": {
      const ip = p.subject.ip ? parseIp(p.subject.ip) : null;
      return !ip || !live(data.prefix).some((x) => x.vrf === p.subject.vrf && x.role === "network" && containsIp(parseCidr(x.cidr)!, ip));
    }
    default:
      return true;
  }
}

const reconcileNow = route("post", "/api/v1/proposals/reconcile", (ctx) => {
  const principal = requireSession();
  onlyQuery(ctx.url, []);
  requireDecider(principal);
  const at = new Date().toISOString();
  const open = [...reconcileState().proposals.values()].filter((p) => p.state === "open");
  let expired = 0;
  let revision: number | null = null;
  for (const p of open) {
    if (stillHolds(p)) continue;
    const next = commit({ ...p, state: "expired", reason: REASON_GONE, decided: { at, by: RECONCILER }, updated: at });
    appendAudit({ action: "ipam.proposal.expire", objects: [{ kind: "proposal", id: p.id }], principal: RECONCILER, source_ip: null });
    revision = next.revision ?? revision;
    expired += 1;
  }
  const report: S["ReconcileReport"] = {
    at,
    opened: 0,
    refreshed: 0,
    unchanged: open.length - expired,
    superseded: 0,
    expired,
    suppressed: 0,
    adopted: 0,
    adoption_failures: 0,
    sightings: 0,
    moves_confirmed: 0,
    revision,
  };
  return ok(report);
});

// ---------------------------------------------------------------------------------
// Adoption policies

const DEFAULT_POLICY: AdoptionPolicy = { mode: "manual", only_dhcp_pools: false, vendors: [], min_sightings: 1, host_mode: "dynamic" };
const POLICY_FIELDS = ["mode", "only_dhcp_pools", "vendors", "min_sightings", "host_mode"] as const;
const MODES = ["manual", "adopt_hosts", "adopt_all"] as const;
const HOST_MODES = ["dynamic", "reserved", "static", "unmanaged"] as const;

function livePrefix(id: string): S["Prefix"] {
  requireId(id);
  const prefix = ipamState().data.prefix.get(id);
  if (!prefix) throw notFound("prefix", id);
  if (prefix.meta.deleted) throw objectDeleted("prefix", id);
  return prefix;
}

/** The view of a prefix's policy: its own, and the one in force (own, inherited or the default). */
function policyView(prefix: S["Prefix"]): S["PolicyView"] {
  const { policies } = reconcileState();
  const own = policies.get(prefix.id);
  let source: S["Prefix"] | null = own ? prefix : null;
  if (!own) {
    const inner = parseCidr(prefix.cidr)!;
    for (const other of ipamState().data.prefix.values()) {
      if (other.id === prefix.id || other.meta.deleted || other.vrf !== prefix.vrf || !policies.has(other.id)) continue;
      const outer = parseCidr(other.cidr)!;
      if (outer.length >= inner.length || !containsCidr(outer, inner)) continue;
      if (!source || parseCidr(source.cidr)!.length < outer.length) source = other;
    }
  }
  const effective = source ? policies.get(source.id)!.policy : DEFAULT_POLICY;
  return {
    prefix: prefix.id,
    policy: own?.policy ?? null,
    updated: own?.updated ?? null,
    effective,
    source: source?.id ?? null,
    revision: own?.revision ?? 0,
  };
}

function invalidPolicy(field: string, detail: string): Problem {
  return new Problem("ipam.adoption.invalid", { status: 400, detail, params: { field } });
}

/** Reads a policy body with its defaults; unknown fields and invalid values are refused. */
function readPolicy(body: Record<string, unknown>): AdoptionPolicy {
  for (const key of Object.keys(body)) {
    if (!(POLICY_FIELDS as readonly string[]).includes(key)) throw invalidPolicy(key, `\`${key}\` is not a field of an adoption policy`);
  }
  if (!MODES.includes(body.mode as (typeof MODES)[number])) throw invalidPolicy("mode", `mode must be one of ${MODES.join(", ")}`);
  const policy: AdoptionPolicy = { ...DEFAULT_POLICY, mode: body.mode as AdoptionPolicy["mode"] };
  if (body.only_dhcp_pools !== undefined) {
    if (typeof body.only_dhcp_pools !== "boolean") throw invalidPolicy("only_dhcp_pools", "only_dhcp_pools must be true or false");
    policy.only_dhcp_pools = body.only_dhcp_pools;
  }
  if (body.vendors !== undefined) {
    const vendors = body.vendors;
    if (!Array.isArray(vendors) || vendors.length > 32 || !vendors.every((v) => typeof v === "string" && v.length >= 1 && v.length <= 64)) {
      throw invalidPolicy("vendors", "vendors is a list of at most 32 entries of 1 to 64 characters");
    }
    policy.vendors = vendors as string[];
  }
  if (body.min_sightings !== undefined) {
    const n = body.min_sightings;
    if (typeof n !== "number" || !Number.isInteger(n) || n < 1 || n > 1000) throw invalidPolicy("min_sightings", "min_sightings must be from 1 to 1,000");
    policy.min_sightings = n;
  }
  if (body.host_mode !== undefined) {
    if (!HOST_MODES.includes(body.host_mode as (typeof HOST_MODES)[number])) throw invalidPolicy("host_mode", `host_mode must be one of ${HOST_MODES.join(", ")}`);
    policy.host_mode = body.host_mode as AdoptionPolicy["host_mode"];
  }
  return policy;
}

/** `If-Match` against the revision of the prefix's own policy (`"0"`: it has none). */
function checkPolicyRevision(prefix: S["Prefix"], ifMatch: number | "*" | null): void {
  if (ifMatch === null || ifMatch === "*") return;
  const actual = reconcileState().policies.get(prefix.id)?.revision ?? 0;
  if (ifMatch !== actual) {
    throw new Problem("ipam.revision_mismatch", {
      status: 412,
      detail: `the adoption policy of prefix ${prefix.id} is at revision ${actual}, not ${ifMatch}`,
      params: { kind: "prefix", id: prefix.id, expected: String(ifMatch), actual: String(actual) },
    });
  }
}

function policyEvent(prefix: S["Prefix"]): number {
  return recordEvent("ipam", { objects: [{ kind: "prefix", id: prefix.id }], tables: ["ipam.adoption"] }).id ?? db.revision;
}

const getAdoption = route("get", "/api/v1/prefixes/{id}/adoption", (ctx) => {
  requireSession();
  onlyQuery(ctx.url, ["at_least"]);
  const view = policyView(livePrefix(ctx.params.id));
  return ok(view, etag(view.revision));
});

const setAdoption = route("put", "/api/v1/prefixes/{id}/adoption", async (ctx) => {
  requireSession();
  onlyQuery(ctx.url, []);
  const prefix = livePrefix(ctx.params.id);
  const policy = readPolicy((await ctx.body()) as Record<string, unknown>);
  checkPolicyRevision(prefix, ctx.ifMatch());
  const { policies } = reconcileState();
  const old = policies.get(prefix.id);
  if (!old || JSON.stringify(old.policy) !== JSON.stringify(policy)) {
    const revision = policyEvent(prefix);
    policies.set(prefix.id, { policy, revision, updated: { at: new Date().toISOString(), by: principalNow() } });
    appendAudit({
      action: "ipam.adoption.set",
      objects: [{ kind: "prefix", id: prefix.id }],
      changes: [{ field: "adoption", old: old ? JSON.stringify(old.policy) : null, new: JSON.stringify(policy) }],
    });
  }
  const view = policyView(prefix);
  return ok(view, etag(view.revision));
});

const clearAdoption = route("delete", "/api/v1/prefixes/{id}/adoption", (ctx) => {
  requireSession();
  onlyQuery(ctx.url, []);
  const prefix = livePrefix(ctx.params.id);
  checkPolicyRevision(prefix, ctx.ifMatch());
  const { policies } = reconcileState();
  const old = policies.get(prefix.id);
  if (old) {
    policies.delete(prefix.id);
    policyEvent(prefix);
    appendAudit({
      action: "ipam.adoption.clear",
      objects: [{ kind: "prefix", id: prefix.id }],
      changes: [{ field: "adoption", old: JSON.stringify(old.policy), new: null }],
    });
  }
  const view = policyView(prefix);
  return ok(view, etag(view.revision));
});

export const reconcileRoutes: HttpHandler[] = [
  observations,
  observation,
  // The static path before the parameterised one.
  reconcileNow,
  proposals,
  proposal,
  approve,
  reject,
  keep,
  approveMany,
  rejectMany,
  getAdoption,
  setAdoption,
  clearAdoption,
];
