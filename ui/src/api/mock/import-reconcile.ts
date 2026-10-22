// Reconcile: the import model against the IPAM state of the mock, item by item, into IPAM
// commands (crates/tenko-ipam/src/import/reconcile.rs).
//
// Every model item is looked up by its natural key (tenant, VRF and site name, VLAN id, CIDR,
// host name, interface name, address). A missing item becomes a create command with a
// client-chosen identifier, so later commands of the same list refer to it; an existing item
// that differs in a field the source sets becomes an update under the conflict policy; an
// equal item becomes nothing. Reconciling the same model twice therefore plans nothing the
// second time (idempotent re-apply, and the empty plan of the round trip). The import never
// deletes and never clears a field the source leaves empty; tags are added, not replaced.
//
// Simplification: VRFs are found by name across tenants, so an export of a store with VRFs of
// several tenants imports back unchanged.
import { cidrOf, containsCidr, formatCidr, formatIp, parseCidr, parseIp, type Cidr } from "../../ipam/ip";
import type {
  Address,
  CustomFieldDef,
  CustomKind,
  CustomValue,
  Host,
  Interface,
  Meta,
  Prefix,
  Vlan,
} from "../types";
import { KnownPrefixes, vrfKey, type ImportModel, type ItemKey, type Loc, type LossEntry, type ModelAddress, type ModelHost, type ModelPrefix, type ModelVlan, type Role } from "./import-model";
import type { Options } from "./import-mapping";
import { LOSS } from "./import-vocab";
import { statusTransitionAllowed } from "./ipam/workspace";
import { ipamState } from "./ipam/api";
import { liveOf } from "./ipam/state";
import * as tf from "./import-transform";
import { randomId } from "./util";

export type ItemAction = "create" | "update" | "unchanged" | "kept";

export interface ItemOutcome {
  key: ItemKey;
  action: ItemAction;
  /** The fields that differ (update or kept). */
  fields: string[];
}

export interface Command {
  op: string;
  args: Record<string, unknown>;
}

/** A credential to write for a host. */
export interface CredentialOp {
  host: string;
}

export interface Reconciled {
  commands: Command[];
  outcomes: ItemOutcome[];
  credentials: CredentialOp[];
  /** Problems found on the way (conflicts kept, invalid tags or custom values). */
  issues: LossEntry[];
  /** Whether a conflict under the `fail` policy blocks the import. */
  blocked: boolean;
  /** The supernet steps: existing networks turned into supernets, with the number of imported networks inside each. */
  supernetSteps: Map<string, number>;
}

const DEFAULT_NAME = "default";

function isDefault(name: string): boolean {
  return name.toLowerCase() === DEFAULT_NAME;
}

/** The live prefixes of the store by VRF name (lowercase), for translation. */
export function knownPrefixes(): KnownPrefixes {
  const data = ipamState().data;
  const names = new Map<string, string>();
  for (const vrf of liveOf(data, "vrf")) names.set(vrf.id, vrf.name.toLowerCase());
  const byVrf = new Map<string, { net: Cidr; role: Role }[]>();
  for (const prefix of liveOf(data, "prefix")) {
    const name = names.get(prefix.vrf);
    if (name === undefined) continue;
    const [text, length] = prefix.cidr.split("/");
    const net = parseNet(text ?? "", Number(length));
    if (!net) continue;
    const list = byVrf.get(name) ?? [];
    list.push({ net, role: prefix.role });
    byVrf.set(name, list);
  }
  return new KnownPrefixes(byVrf);
}

function parseNet(text: string, length: number): Cidr | null {
  const ip = parseIp(text);
  return ip ? cidrOf(ip, length) : null;
}

const URL_PATTERN = /^(https?|ftp|ssh|rdp):\/\/\S+$/i;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

function validDate(text: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  if (!match) return false;
  const [year, month, day] = [Number(match[1]), Number(match[2]), Number(match[3])];
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

/** A custom value from text, or the reason it is not one. */
function parseCustom(kind: CustomKind, raw: string): CustomValue | string {
  const text = raw.trim();
  switch (kind.type) {
    case "text":
      return Array.from(text).length > 1024 || CONTROL.test(text) ? `\`${text}\` is not a valid text` : { type: "text", value: text };
    case "integer":
      return /^[+-]?[0-9]+$/.test(text) && Number.isSafeInteger(Number(text))
        ? { type: "integer", value: Number(text) }
        : `\`${text}\` is not a 64-bit integer`;
    case "boolean": {
      const value = tf.boolean(text);
      return value === null || text.toLowerCase() === "x" || text.toLowerCase() === "y" || text.toLowerCase() === "j"
        ? `\`${text}\` is not a boolean (true, false, yes, no, 1, 0, ja or nej)`
        : { type: "boolean", value };
    }
    case "date":
      return validDate(text) ? { type: "date", value: text } : `\`${text}\` is not a date as YYYY-MM-DD`;
    case "url":
      return URL_PATTERN.test(text) && text.length <= 2048 ? { type: "url", value: text } : `\`${text}\` is not a URL`;
    case "select": {
      const option = kind.options.find((o) => o === text) ?? kind.options.find((o) => o.toLowerCase() === text.toLowerCase());
      return option === undefined ? `\`${text}\` is not one of the ${kind.options.length} allowed options` : { type: "select", value: option };
    }
  }
}

function sameJson(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

type MetaKindName = "prefix" | "host" | "address";

class Reconciler {
  readonly out: Reconciled = { commands: [], outcomes: [], credentials: [], issues: [], blocked: false, supernetSteps: new Map() };
  private readonly data = ipamState().data;
  private readonly defs = new Map<string, CustomFieldDef>();
  private readonly reportedUndefined = new Set<string>();
  private readonly tenantIds = new Map<string, string>();
  private readonly vrfIds = new Map<string, string>();
  private readonly siteIds = new Map<string, string>();
  private readonly vlanIds = new Map<string, string>();
  private readonly vlanById = new Map<string, Vlan>();
  private readonly hostIds = new Map<string, string>();
  private readonly hostById = new Map<string, Host>();
  private readonly prefixIdx = new Map<string, Prefix>();
  private readonly addressIdx = new Map<string, Address>();
  private readonly interfacesOf = new Map<string, Map<string, Interface>>();
  private readonly interfaceIds = new Map<string, string>();

  constructor(
    private readonly model: ImportModel,
    private readonly options: Options,
  ) {
    const data = this.data;
    for (const def of data.custom_field.values()) this.defs.set(def.key, def);
    const tenantNames = new Map<string, string>();
    for (const t of liveOf(data, "tenant")) {
      this.tenantIds.set(t.name.toLowerCase(), t.id);
      tenantNames.set(t.id, t.name.toLowerCase());
    }
    for (const v of liveOf(data, "vrf")) if (!this.vrfIds.has(v.name.toLowerCase())) this.vrfIds.set(v.name.toLowerCase(), v.id);
    for (const s of liveOf(data, "site")) this.siteIds.set(s.name.toLowerCase(), s.id);
    for (const v of liveOf(data, "vlan")) {
      this.vlanIds.set(`${v.site ?? ""}|${v.vid}`, v.id);
      this.vlanById.set(v.id, v);
    }
    for (const h of liveOf(data, "host")) {
      this.hostIds.set(`${tenantNames.get(h.tenant) ?? ""}|${h.name}`, h.id);
      this.hostById.set(h.id, h);
    }
    for (const p of liveOf(data, "prefix")) this.prefixIdx.set(`${p.vrf}|${p.cidr}`, p);
    for (const a of liveOf(data, "address")) this.addressIdx.set(`${a.vrf}|${a.ip}`, a);
    for (const i of liveOf(data, "interface")) {
      const list = this.interfacesOf.get(i.host) ?? new Map<string, Interface>();
      list.set(i.name, i);
      this.interfacesOf.set(i.host, list);
      this.interfaceIds.set(`${i.host}|${i.name}`, i.id);
    }
  }

  private issue(location: Loc, code: string, detail: string): void {
    this.out.issues.push({ location, code, detail });
  }

  private outcome(key: ItemKey, action: ItemAction, fields: string[] = []): void {
    this.out.outcomes.push({ key, action, fields });
  }

  private command(op: string, args: Record<string, unknown>): void {
    this.out.commands.push({ op, args });
  }

  /** Applies the conflict policy to a difference: whether the update goes ahead. */
  private conflict(key: ItemKey, fields: readonly string[], location: Loc): boolean {
    const policy = this.options.conflict;
    if (policy === "update") return true;
    this.issue(
      location,
      LOSS.conflictKept,
      `${labelOf(key)} differs from the store in ${fields.join(", ")}; ${policy === "fail" ? "the conflict policy refuses the import" : "the store's values are kept"}`,
    );
    if (policy === "fail") this.out.blocked = true;
    return false;
  }

  // ----- names -----------------------------------------------------------------------

  private tenantId(name: string | null): string | null {
    return this.tenantIds.get((name ?? this.options.tenant ?? DEFAULT_NAME).toLowerCase()) ?? null;
  }

  private vrfId(name: string | null): string | null {
    return this.vrfIds.get(vrfKey(name, this.options.vrf)) ?? null;
  }

  /** The VRF field of a new object: undefined for the default VRF. */
  private vrfInput(name: string | null): string | undefined {
    if (isDefault(vrfKey(name, this.options.vrf))) return undefined;
    return this.vrfId(name) ?? undefined;
  }

  /** The tenant field of a new object: undefined for the default tenant. */
  private tenantInput(name: string | null): string | undefined {
    const wanted = name ?? this.options.tenant;
    return wanted !== null && !isDefault(wanted) ? (this.tenantId(wanted) ?? undefined) : undefined;
  }

  private siteId(name: string | null): string | null {
    return name === null ? null : (this.siteIds.get(name.toLowerCase()) ?? null);
  }

  private vlanId(site: string | null, vid: number): string | null {
    return this.vlanIds.get(`${this.siteId(site) ?? ""}|${vid}`) ?? null;
  }

  private hostKey(tenant: string | null, name: string): string {
    return `${(tenant ?? this.options.tenant ?? DEFAULT_NAME).toLowerCase()}|${name}`;
  }

  private hostId(tenant: string | null, name: string): string | null {
    return this.hostIds.get(this.hostKey(tenant, name)) ?? null;
  }

  // ----- metadata --------------------------------------------------------------------

  private tags(tags: readonly string[], location: Loc): string[] {
    const set = new Set<string>();
    for (const tag of tags) {
      if (tag === "" || Array.from(tag).length > 64 || CONTROL.test(tag)) {
        this.issue(location, LOSS.valueInvalid, `\`${tag}\` is not a valid tag; it is left out`);
      } else {
        set.add(tag);
      }
    }
    return [...set].sort();
  }

  private custom(kind: MetaKindName, values: Record<string, string>, location: Loc): Record<string, CustomValue> {
    const out: Record<string, CustomValue> = {};
    for (const [key, text] of Object.entries(values)) {
      const def = this.defs.get(key);
      if (!def) {
        if (!this.reportedUndefined.has(key)) {
          this.reportedUndefined.add(key);
          this.issue(location, LOSS.customUndefined, `the custom field \`${key}\` is not defined; its values are left out`);
        }
        continue;
      }
      if (!def.applies_to.includes(kind)) {
        this.issue(location, LOSS.valueInvalid, `the custom field \`${key}\` does not apply to ${kind} objects; the value is left out`);
        continue;
      }
      const parsed = parseCustom(def.kind, text);
      if (typeof parsed === "string") this.issue(location, LOSS.valueInvalid, `${parsed}; the value is left out`);
      else out[key] = parsed;
    }
    return out;
  }

  /**
   * Compares the metadata the source sets with the stored metadata: the description when it
   * differs, the union of tags when the source adds one, the custom values that differ.
   */
  private metaPatch(
    meta: Meta,
    description: string | null,
    tags: readonly string[],
    custom: Record<string, CustomValue>,
    fields: string[],
  ): Record<string, unknown> {
    const patch: Record<string, unknown> = {};
    if (description !== null && (meta.description ?? null) !== description.trim()) {
      patch.description = description;
      fields.push("description");
    }
    const have = new Set(meta.tags ?? []);
    if (!tags.every((t) => have.has(t))) {
      patch.tags = [...new Set([...have, ...tags])].sort();
      fields.push("tags");
    }
    const changed: Record<string, CustomValue> = {};
    for (const [key, value] of Object.entries(custom)) {
      if (!sameJson((meta.custom as Record<string, unknown>)[key], value)) changed[key] = value;
    }
    if (Object.keys(changed).length > 0) {
      patch.custom = changed;
      for (const key of Object.keys(changed)) fields.push(`custom.${key}`);
    }
    return patch;
  }

  // ----- items -----------------------------------------------------------------------

  run(): Reconciled {
    const model = this.model;
    const tenants = new Map<string, string>();
    const vrfs = new Map<string, string>();
    const sites = new Map<string, string>();
    const add = (set: Map<string, string>, name: string | null): void => {
      if (name !== null && !isDefault(name) && !set.has(name.toLowerCase())) set.set(name.toLowerCase(), name);
    };
    add(tenants, this.options.tenant);
    add(vrfs, this.options.vrf);
    for (const host of model.hosts) {
      add(tenants, host.tenant);
      add(sites, host.site);
    }
    for (const prefix of model.prefixes) {
      add(vrfs, prefix.vrf);
      add(sites, prefix.site);
    }
    for (const vlan of model.vlans) add(sites, vlan.site);
    for (const address of model.addresses) add(vrfs, address.vrf);
    for (const key of [...tenants.keys()].sort()) this.tenant(tenants.get(key) as string);
    for (const key of [...vrfs.keys()].sort()) this.vrf(vrfs.get(key) as string);
    for (const key of [...sites.keys()].sort()) this.site(sites.get(key) as string);
    for (const vlan of model.vlans) this.vlan(vlan);
    for (const prefix of model.prefixes) this.prefix(prefix);
    for (const host of model.hosts) this.host(host);
    for (const address of model.addresses) this.address(address);
    return this.out;
  }

  private tenant(name: string): void {
    if (this.tenantId(name) !== null) return;
    const id = randomId();
    this.tenantIds.set(name.toLowerCase(), id);
    this.command("create_tenant", { id, name });
  }

  private vrf(name: string): void {
    if (this.vrfId(name) !== null) return;
    const id = randomId();
    const tenant = this.tenantInput(null);
    this.vrfIds.set(name.toLowerCase(), id);
    this.command("create_vrf", { id, ...(tenant ? { tenant } : {}), name });
  }

  private site(name: string): void {
    if (this.siteId(name) !== null) return;
    const id = randomId();
    this.siteIds.set(name.toLowerCase(), id);
    this.command("create_site", { id, name });
  }

  private vlan(vlan: ModelVlan): void {
    const key: ItemKey = vlan.site !== null ? { kind: "vlan", site: vlan.site, vid: vlan.vid } : { kind: "vlan", vid: vlan.vid };
    const site = this.siteId(vlan.site);
    const id = this.vlanId(vlan.site, vlan.vid);
    if (id === null) {
      const fresh = randomId();
      this.vlanIds.set(`${site ?? ""}|${vlan.vid}`, fresh);
      this.command("create_vlan", { id: fresh, vid: vlan.vid, name: vlan.name ?? `VLAN ${vlan.vid}`, ...(site ? { site } : {}) });
      this.outcome(key, "create");
      return;
    }
    const existing = this.vlanById.get(id);
    if (!existing) return;
    const differs = vlan.name !== null && vlan.name !== existing.name;
    if (differs && this.conflict(key, ["name"], vlan.origin)) {
      this.command("update_vlan", { id, expected: null, patch: { name: vlan.name } });
      this.outcome(key, "update", ["name"]);
    } else {
      this.outcome(key, differs ? "kept" : "unchanged");
    }
  }

  private alarm(prefix: ModelPrefix, existing: Prefix["alarm"]): Prefix["alarm"] {
    const warn = prefix.alarmWarn ?? existing?.warn_pct;
    const crit = prefix.alarmCrit ?? existing?.crit_pct;
    if (warn === undefined || crit === undefined) return null;
    if (prefix.alarmWarn === null && prefix.alarmCrit === null) return existing ?? null;
    if (warn < crit && crit <= 100) return { warn_pct: warn, crit_pct: crit };
    this.issue(
      prefix.origin,
      LOSS.valueInvalid,
      `the alarm thresholds ${warn}/${crit} of ${formatCidr(prefix.cidr)} are not ordered; they are left out`,
    );
    return existing ?? null;
  }

  private prefix(prefix: ModelPrefix): void {
    const key: ItemKey = { kind: "prefix", vrf: vrfKey(prefix.vrf, this.options.vrf), cidr: formatCidr(prefix.cidr) };
    const vlan = prefix.vlan === null ? null : this.vlanId(prefix.site, prefix.vlan);
    const site = this.siteId(prefix.site);
    const tags = this.tags(prefix.tags, prefix.origin);
    const custom = this.custom("prefix", prefix.custom, prefix.origin);
    const vrfId = this.vrfId(prefix.vrf);
    const existing = vrfId === null ? undefined : this.prefixIdx.get(`${vrfId}|${formatCidr(prefix.cidr)}`);
    if (!existing) {
      if (vrfId !== null && !this.supernetStep(prefix, vrfId)) {
        this.outcome(key, "kept");
        return;
      }
      const alarm = this.alarm(prefix, null);
      const vrf = this.vrfInput(prefix.vrf);
      this.command("create_prefix", {
        id: randomId(),
        ...(vrf ? { vrf } : {}),
        cidr: formatCidr(prefix.cidr),
        ...(prefix.role ? { role: prefix.role } : {}),
        ...(prefix.status ? { status: prefix.status } : {}),
        ...(vlan ? { vlan } : {}),
        ...(site ? { site } : {}),
        ...(alarm ? { alarm } : {}),
        ...(prefix.alloc ? { alloc: prefix.alloc } : {}),
        tags,
        custom,
        ...(prefix.description !== null ? { description: prefix.description } : {}),
      });
      this.outcome(key, "create");
      return;
    }
    const patch: Record<string, unknown> = {};
    const fields: string[] = [];
    if (prefix.role !== null && prefix.role !== existing.role) {
      patch.role = prefix.role;
      fields.push("role");
      // The networks of the import inside it need no supernet step of their own.
      if (prefix.role === "supernet" && !this.out.supernetSteps.has(existing.id)) this.out.supernetSteps.set(existing.id, 0);
    }
    if (prefix.status !== null && prefix.status !== existing.status) {
      if (statusTransitionAllowed(existing.status, prefix.status as Prefix["status"])) {
        patch.status = prefix.status;
        fields.push("status");
      } else {
        this.transitionIssue(key, existing.status, prefix.status, prefix.origin);
      }
    }
    if (prefix.vlan !== null && vlan !== (existing.vlan ?? null)) {
      patch.vlan = vlan;
      fields.push("vlan");
    }
    if (prefix.site !== null && site !== (existing.site ?? null)) {
      patch.site = site;
      fields.push("site");
    }
    const alarm = this.alarm(prefix, existing.alarm ?? null);
    if (!sameJson(alarm, existing.alarm ?? null)) {
      patch.alarm = alarm;
      fields.push("alarm");
    }
    if (prefix.alloc !== null && prefix.alloc !== existing.alloc) {
      patch.alloc = prefix.alloc;
      fields.push("alloc");
    }
    Object.assign(patch, this.metaPatch(existing.meta, prefix.description, tags, custom, fields));
    this.finishUpdate("update_prefix", existing.id, key, patch, fields, prefix.origin);
  }

  /**
   * The supernet step: a new network inside an existing network of the store turns that network
   * into a supernet, once, instead of failing every network inside it with an overlap. A network
   * with ranges stays a network: the imported network is left out and its addresses go to it.
   * Returns whether the imported network can be created.
   */
  private supernetStep(prefix: ModelPrefix, vrfId: string): boolean {
    let parent: Prefix | undefined;
    let parentLength = -1;
    for (const other of this.prefixIdx.values()) {
      if (other.vrf !== vrfId) continue;
      const there = parseCidr(other.cidr);
      if (!there || there.version !== prefix.cidr.version || there.length >= prefix.cidr.length) continue;
      if (containsCidr(there, prefix.cidr) && there.length > parentLength) {
        parent = other;
        parentLength = there.length;
      }
    }
    if (!parent || parent.role !== "network") return true;
    const count = this.out.supernetSteps.get(parent.id);
    if (count !== undefined) {
      this.out.supernetSteps.set(parent.id, count + 1);
      return true;
    }
    const ranges = [...this.data.range.values()].some((r) => r.prefix === (parent as Prefix).id && !r.meta.deleted);
    if (ranges) {
      this.issue(
        prefix.origin,
        LOSS.prefixInNetwork,
        `${formatCidr(prefix.cidr)} lies in the network ${parent.cidr}, which stays a network because it has ranges; ${formatCidr(prefix.cidr)} is not created and its addresses go to ${parent.cidr}`,
      );
      return false;
    }
    this.command("update_prefix", { id: parent.id, expected: null, patch: { role: "supernet" } });
    this.out.supernetSteps.set(parent.id, 1);
    this.outcome({ kind: "prefix", vrf: vrfKey(prefix.vrf, this.options.vrf), cidr: parent.cidr }, "update", ["role"]);
    return true;
  }

  private finishUpdate(op: string, id: string, key: ItemKey, patch: Record<string, unknown>, fields: string[], origin: Loc): void {
    if (fields.length === 0) this.outcome(key, "unchanged");
    else if (this.conflict(key, fields, origin)) {
      this.command(op, { id, expected: null, patch });
      this.outcome(key, "update", fields);
    } else {
      this.outcome(key, "kept", fields);
    }
  }

  private transitionIssue(key: ItemKey, from: string, to: string, origin: Loc): void {
    this.issue(origin, LOSS.valueInvalid, `${labelOf(key)} cannot change status from ${from} to ${to}; the status is left as it is`);
  }

  private interfaceInput(iface: { name: string; mac: string | null; duid: string | null; clientId: string | null }, host?: string) {
    return {
      id: randomId(),
      ...(host ? { host } : {}),
      name: iface.name,
      ...(iface.mac ? { mac: iface.mac } : {}),
      ...(iface.duid ? { duid: iface.duid } : {}),
      ...(iface.clientId ? { client_id: iface.clientId } : {}),
    };
  }

  private host(host: ModelHost): void {
    const key: ItemKey = { kind: "host", name: host.name };
    const site = this.siteId(host.site);
    const tags = this.tags(host.tags, host.origin);
    const custom = this.custom("host", host.custom, host.origin);
    const existingId = this.hostId(host.tenant, host.name);
    const existing = existingId === null ? undefined : this.hostById.get(existingId);
    let id: string;
    if (!existing) {
      id = randomId();
      const tenant = this.tenantInput(host.tenant);
      const interfaces = host.interfaces.map((i) => this.interfaceInput(i));
      this.hostIds.set(this.hostKey(host.tenant, host.name), id);
      host.interfaces.forEach((iface, index) => {
        this.interfaceIds.set(`${id}|${iface.name}`, interfaces[index]?.id as string);
        this.outcome({ kind: "interface", host: host.name, name: iface.name }, "create");
      });
      this.command("create_host", {
        id,
        ...(tenant ? { tenant } : {}),
        name: host.name,
        ...(host.mode ? { mode: host.mode } : {}),
        ...(host.lock !== null ? { lock: host.lock } : {}),
        ...(site ? { site } : {}),
        interfaces,
        tags,
        custom,
        ...(host.description !== null ? { description: host.description } : {}),
      });
      this.outcome(key, "create");
    } else {
      id = existing.id;
      const patch: Record<string, unknown> = {};
      const fields: string[] = [];
      if (host.mode !== null && host.mode !== existing.mode) {
        patch.mode = host.mode;
        fields.push("mode");
      }
      if (host.lock !== null && host.lock !== existing.lock) {
        patch.lock = host.lock;
        fields.push("lock");
      }
      if (host.site !== null && site !== (existing.site ?? null)) {
        patch.site = site;
        fields.push("site");
      }
      Object.assign(patch, this.metaPatch(existing.meta, host.description, tags, custom, fields));
      this.finishUpdate("update_host", existing.id, key, patch, fields, host.origin);
      this.hostInterfacesUpdate(host, existing.id);
    }
    if (this.options.credentials === "import" && this.model.credentials.some((c) => c.host === host.name)) {
      this.out.credentials.push({ host: host.name });
    }
  }

  private hostInterfacesUpdate(host: ModelHost, hostId: string): void {
    const existing = this.interfacesOf.get(hostId) ?? new Map<string, Interface>();
    for (const iface of host.interfaces) {
      const key: ItemKey = { kind: "interface", host: host.name, name: iface.name };
      const current = existing.get(iface.name);
      if (!current) {
        const input = this.interfaceInput(iface, hostId);
        this.interfaceIds.set(`${hostId}|${iface.name}`, input.id);
        this.command("create_interface", input);
        this.outcome(key, "create");
        continue;
      }
      const patch: Record<string, unknown> = {};
      const fields: string[] = [];
      if (iface.mac !== null && iface.mac !== current.mac) {
        patch.mac = iface.mac;
        fields.push("mac");
      }
      if (iface.duid !== null && iface.duid.replace(/:/g, "") !== (current.duid ?? "").replace(/:/g, "")) {
        patch.duid = iface.duid;
        fields.push("duid");
      }
      const currentClient = (current.client_id ?? "").replace(/:/g, "").toLowerCase();
      if (iface.clientId !== null && iface.clientId !== currentClient) {
        patch.client_id = iface.clientId;
        fields.push("client_id");
      }
      this.finishUpdate("update_interface", current.id, key, patch, fields, iface.origin);
    }
  }

  /** The interface an address goes on: known from this run or the store. */
  private interfaceOf(address: ModelAddress): string | null {
    if (address.host === null || address.interface === null) return null;
    const tenant = this.model.hosts.find((h) => h.name === address.host)?.tenant ?? null;
    const hostId = this.hostId(tenant, address.host);
    return hostId === null ? null : (this.interfaceIds.get(`${hostId}|${address.interface}`) ?? null);
  }

  private address(address: ModelAddress): void {
    const key: ItemKey = { kind: "address", vrf: vrfKey(address.vrf, this.options.vrf), ip: formatIp(address.ip) };
    const tags = this.tags(address.tags, address.origin);
    const custom = this.custom("address", address.custom, address.origin);
    const iface = this.interfaceOf(address);
    const vrfId = this.vrfId(address.vrf);
    const existing = vrfId === null ? undefined : this.addressIdx.get(`${vrfId}|${formatIp(address.ip)}`);
    if (!existing) {
      const vrf = this.vrfInput(address.vrf);
      this.command("create_address", {
        id: randomId(),
        ...(vrf ? { vrf } : {}),
        ip: formatIp(address.ip),
        ...(address.status ? { status: address.status } : {}),
        ...(iface ? { interface: iface } : {}),
        ...(address.dnsName ? { dns_name: address.dnsName } : {}),
        tags,
        custom,
        ...(address.description !== null ? { description: address.description } : {}),
      });
      this.outcome(key, "create");
      return;
    }
    const patch: Record<string, unknown> = {};
    const fields: string[] = [];
    if (address.host !== null && iface !== null && iface !== (existing.interface ?? null)) {
      patch.interface = iface;
      fields.push("interface");
    }
    if (address.status !== null && address.status !== existing.status) {
      if (statusTransitionAllowed(existing.status, address.status as Address["status"])) {
        patch.status = address.status;
        fields.push("status");
      } else {
        this.transitionIssue(key, existing.status, address.status, address.origin);
      }
    }
    if (address.dnsName !== null && address.dnsName !== (existing.dns_name ?? null)) {
      patch.dns_name = address.dnsName;
      fields.push("dns_name");
    }
    Object.assign(patch, this.metaPatch(existing.meta, address.description, tags, custom, fields));
    this.finishUpdate("update_address", existing.id, key, patch, fields, address.origin);
  }
}

function labelOf(key: ItemKey): string {
  switch (key.kind) {
    case "vlan":
      return `VLAN ${key.vid}`;
    case "prefix":
      return `prefix ${key.cidr}`;
    case "host":
      return `host ${key.name}`;
    case "interface":
      return `interface ${key.name} of ${key.host}`;
    case "address":
      return `address ${key.ip}`;
    case "credential":
      return `credential of ${key.host}`;
  }
}

/** Reconciles a model against the IPAM state: commands, outcomes per item, issues. */
export function reconcile(model: ImportModel, options: Options): Reconciled {
  return new Reconciler(model, options).run();
}
