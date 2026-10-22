// The workspace of one plan: a copy of the state the commands change, the changes and
// warnings they produce, and the checks every kind of object shares (metadata, custom
// values, status transitions, references, the DHCP pool rule). The kinds' own rules live in
// plan-tenancy.ts, plan-space.ts and plan-hosts.ts.
import type {
  Address,
  AssignmentMode,
  ChangeAction,
  CustomFieldDef,
  CustomKind,
  FieldChange,
  Host,
  Interface,
  IpamObject,
  Meta,
  ObjectRef,
  PlannedChange,
  PlanWarning,
  Prefix,
  Principal,
  Range,
  Stamp,
  Status,
} from "../../types";
import { Problem, fieldError } from "../reply";
import { randomId } from "../util";
import { isJson, type MetaInput } from "./input";
import { ipOf } from "./net";
import {
  idTaken,
  nameTaken,
  notDeleted,
  notFound,
  objectDeleted,
  referenceMissing,
  revisionMismatch,
} from "./problems";
import { cloneData, liveOf, objectOf, type IpamData, type Kind, type KindTypes, type MetaKind } from "./state";

// ---------------------------------------------------------------------------------
// Field differences

const IGNORED = new Set(["meta.revision", "meta.updated"]);

function flatten(object: IpamObject): Map<string, unknown> {
  const out = new Map<string, unknown>();
  for (const [key, value] of Object.entries(object.data as unknown as Record<string, unknown>)) {
    if (key === "meta" && isJson(value)) {
      for (const [inner, entry] of Object.entries(value)) out.set(`meta.${inner}`, entry);
    } else {
      out.set(key, value);
    }
  }
  return out;
}

function render(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") return value;
  if (Array.isArray(value) && value.length === 0) return null;
  if (isJson(value) && Object.keys(value).length === 0) return null;
  return JSON.stringify(value);
}

/**
 * The changed fields between two versions of an object, rendered as text and sorted by
 * field path (`meta.tags` for the metadata); the revision and the update stamp never count.
 */
export function diffObjects(before: IpamObject | null, after: IpamObject | null): FieldChange[] {
  const old = before ? flatten(before) : new Map<string, unknown>();
  const now = after ? flatten(after) : new Map<string, unknown>();
  const keys = [...new Set([...old.keys(), ...now.keys()])].filter((key) => !IGNORED.has(key)).sort();
  const out: FieldChange[] = [];
  for (const key of keys) {
    const was = render(old.get(key));
    const is = render(now.get(key));
    if (was === is) continue;
    out.push({ field: key, ...(was !== null ? { old: was } : {}), ...(is !== null ? { new: is } : {}) });
  }
  return out;
}

// ---------------------------------------------------------------------------------
// Rules shared by several kinds

/** Whether a status may change from `from` to `to` (IPAM-05). Staying is always allowed. */
export function statusTransitionAllowed(from: Status, to: Status): boolean {
  if (from === to) return true;
  switch (from) {
    case "planned":
      return to === "active" || to === "reserved" || to === "deprecated";
    case "reserved":
      return to === "planned" || to === "active" || to === "deprecated";
    case "active":
      return to === "reserved" || to === "deprecated";
    case "deprecated":
      return to === "active";
  }
}

export const CUSTOM = {
  unknown: "ipam.custom_field.unknown",
  notApplicable: "ipam.custom_field.not_applicable",
  typeMismatch: "ipam.custom_field.type_mismatch",
  invalid: "ipam.custom_field.invalid",
  required: "ipam.custom_field.required",
} as const;

const URL_PATTERN = /^(https?|ftp|ssh|rdp):\/\/\S+$/i;
// eslint-disable-next-line no-control-regex
const CONTROL_NO_BREAK = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

function validDate(text: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  if (!match) return false;
  const [year, month, day] = [Number(match[1]), Number(match[2]), Number(match[3])];
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

/** What is wrong with a custom value for its definition, or null. */
function customProblem(key: string, kind: CustomKind, value: unknown): { code: string; message: string } | null {
  if (!isJson(value) || typeof value.type !== "string" || !("value" in value)) {
    return { code: CUSTOM.invalid, message: `the value of custom field ${key} must be {type, value}` };
  }
  if (value.type !== kind.type) {
    return {
      code: CUSTOM.typeMismatch,
      message: `custom field ${key} holds ${kind.type} values, not ${value.type}`,
    };
  }
  const inner = value.value;
  const bad = (message: string) => ({ code: CUSTOM.invalid, message });
  switch (kind.type) {
    case "text":
      if (typeof inner !== "string") return bad(`custom field ${key} needs a text`);
      if (Array.from(inner).length > 1024 || CONTROL_NO_BREAK.test(inner)) return bad(`custom field ${key} is not a valid text`);
      return null;
    case "integer":
      return typeof inner === "number" && Number.isSafeInteger(inner) ? null : bad(`custom field ${key} needs an integer`);
    case "boolean":
      return typeof inner === "boolean" ? null : bad(`custom field ${key} needs true or false`);
    case "date":
      return typeof inner === "string" && validDate(inner) ? null : bad(`custom field ${key} needs a date as YYYY-MM-DD`);
    case "url":
      return typeof inner === "string" && inner.length <= 2048 && URL_PATTERN.test(inner)
        ? null
        : bad(`custom field ${key} needs a URL`);
    case "select":
      return typeof inner === "string" && kind.options.includes(inner)
        ? null
        : bad(`custom field ${key} needs one of its options`);
  }
}

/** The principals of automation: a locked host refuses them (IPAM-16). */
export function isAutomation(principal: Principal): boolean {
  if (principal.kind === "node") return true;
  if (principal.kind === "system") {
    return ["reconciler", "connector", "scan", "import"].includes(principal.component);
  }
  return false;
}

// ---------------------------------------------------------------------------------
// The workspace

export class Workspace {
  readonly data: IpamData;
  readonly changes: PlannedChange[] = [];
  readonly warnings: PlanWarning[] = [];
  /** Hosts whose reservation identifiers are checked at the end (IPAM-18). */
  readonly reservationChecks = new Set<string>();
  defaultTenantId: string | null = null;
  defaultVrfId: string | null = null;

  constructor(
    base: IpamData,
    readonly at: string,
    readonly principal: Principal,
  ) {
    this.data = cloneData(base);
  }

  stamp(): Stamp {
    return { at: this.at, by: this.principal };
  }

  /** Turning a network into a supernet warns: the import's supernet step. */
  supernetStep = false;

  get automation(): boolean {
    return isAutomation(this.principal);
  }

  map<K extends Kind>(kind: K): Map<string, KindTypes[K]> {
    return this.data[kind] as Map<string, KindTypes[K]>;
  }

  get<K extends Kind>(kind: K, id: string): KindTypes[K] | undefined {
    return this.map(kind).get(id);
  }

  put<K extends Kind>(kind: K, value: KindTypes[K]): void {
    this.map(kind).set((value as { id: string }).id, value);
  }

  live<K extends MetaKind>(kind: K): KindTypes[K][] {
    return liveOf(this.data, kind);
  }

  // ---- changes and warnings -------------------------------------------------------------

  /** Records one change of one object. */
  record<K extends Kind>(
    kind: K,
    action: ChangeAction,
    before: KindTypes[K] | null,
    after: KindTypes[K] | null,
    derived = false,
  ): void {
    const was = before ? objectOf(kind, structuredClone(before)) : null;
    const is = after ? objectOf(kind, structuredClone(after)) : null;
    const id = ((after ?? before) as { id: string }).id;
    const fields = diffObjects(was, is);
    this.changes.push({
      object: { kind, id },
      action,
      ...(was ? { before: was } : {}),
      ...(is ? { after: is } : {}),
      ...(fields.length > 0 ? { fields } : {}),
      derived,
    });
  }

  warn(
    code: string,
    message: string,
    object: ObjectRef | null,
    params: Record<string, string>,
    requiresAck = false,
  ): void {
    this.warnings.push({
      code,
      message,
      ...(object ? { object } : {}),
      params,
      requires_ack: requiresAck,
      acknowledged: false,
    });
  }

  // ---- loading --------------------------------------------------------------------------

  /** The id for a new object: the client's (which must be unused) or a new one. */
  claimId(kind: Kind, wanted: string | undefined): string {
    if (wanted !== undefined) {
      if (this.map(kind).has(wanted)) throw idTaken(kind, wanted);
      return wanted;
    }
    return randomId();
  }

  /** Loads an object for a change: it must exist, match `expected` and not be deleted. */
  loadForChange<K extends MetaKind>(
    kind: K,
    id: string,
    expected: number | null,
    allowDeleted = false,
  ): KindTypes[K] {
    const found = this.get(kind, id);
    if (!found) throw notFound(kind, id);
    const meta = (found as { meta: Meta }).meta;
    if (expected !== null && expected !== (meta.revision ?? 0)) {
      throw revisionMismatch(kind, id, expected, meta.revision ?? 0);
    }
    if (!allowDeleted && meta.deleted) throw objectDeleted(kind, id);
    return found;
  }

  /** Fails with `ipam.not_deleted` unless the object is soft-deleted (restore needs that). */
  requireDeleted(kind: Kind, id: string, meta: Meta): void {
    if (!meta.deleted) throw notDeleted(kind, id);
  }

  /** Loads a referenced object that must exist and be live. */
  liveRef<K extends MetaKind>(kind: K, id: string, field: string): KindTypes[K] {
    const found = this.get(kind, id);
    if (!found || (found as { meta: Meta }).meta.deleted) throw referenceMissing(field, kind, id);
    return found;
  }

  /** The first live object of a kind that satisfies the test. */
  find<K extends MetaKind>(kind: K, test: (value: KindTypes[K]) => boolean): KindTypes[K] | undefined {
    for (const value of this.map(kind).values()) {
      if (!(value as { meta: Meta }).meta.deleted && test(value)) return value;
    }
    return undefined;
  }

  /** Fails with `ipam.name_taken` when a live object of the kind satisfies the test. */
  assertFree<K extends MetaKind>(
    kind: K,
    label: string,
    name: string,
    taken: (value: KindTypes[K]) => boolean,
    exclude?: string,
  ): void {
    const other = this.find(kind, (value) => (value as { id: string }).id !== exclude && taken(value));
    if (other) throw nameTaken(label, name);
  }

  // ---- metadata -------------------------------------------------------------------------

  /** The custom field definitions by key. */
  definitions(): Map<string, CustomFieldDef> {
    const out = new Map<string, CustomFieldDef>();
    for (const def of this.data.custom_field.values()) out.set(def.key, def);
    return out;
  }

  /** Checks custom values against the definitions (IPAM-08). */
  validateCustom(kind: MetaKind, values: Record<string, unknown>): void {
    const defs = this.definitions();
    const problems: { key: string; code: string; message: string }[] = [];
    for (const [key, value] of Object.entries(values)) {
      const def = defs.get(key);
      if (!def) {
        problems.push({ key, code: CUSTOM.unknown, message: `no custom field ${key} is defined` });
      } else if (!def.applies_to.includes(kind)) {
        problems.push({ key, code: CUSTOM.notApplicable, message: `custom field ${key} does not apply to ${kind}` });
      } else {
        const problem = customProblem(key, def.kind, value);
        if (problem) problems.push({ key, ...problem });
      }
    }
    for (const [key, def] of defs) {
      if (def.required && def.applies_to.includes(kind) && !(key in values)) {
        problems.push({ key, code: CUSTOM.required, message: `custom field ${key} is required for ${kind}` });
      }
    }
    const first = problems.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))[0];
    if (!first) return;
    throw new Problem(first.code, {
      status: 400,
      detail: first.message,
      params: { key: first.key },
      errors: problems.map((p) => fieldError(`custom.${p.key}`, p.code)),
    });
  }

  /** The metadata of a new object. */
  makeMeta(kind: MetaKind, input: MetaInput): Meta {
    const custom: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input.custom ?? {})) if (value !== null) custom[key] = value;
    this.validateCustom(kind, custom);
    return {
      revision: 0,
      created: this.stamp(),
      updated: this.stamp(),
      deleted: null,
      tags: input.tags ?? [],
      custom: custom as Meta["custom"],
      description: input.description ?? null,
    };
  }

  /** Applies the metadata part of a patch to `meta` (a copy the caller owns). */
  patchMeta(kind: MetaKind, meta: Meta, input: MetaInput): void {
    if (input.tags !== undefined) meta.tags = input.tags;
    if (input.description !== undefined) meta.description = input.description;
    if (input.custom !== undefined) {
      const custom: Record<string, unknown> = { ...(meta.custom ?? {}) };
      for (const [key, value] of Object.entries(input.custom)) {
        if (value === null) delete custom[key];
        else custom[key] = value;
      }
      meta.custom = custom as Meta["custom"];
    }
    this.validateCustom(kind, (meta.custom ?? {}) as Record<string, unknown>);
    meta.updated = this.stamp();
  }

  /**
   * Replaces an object by its changed copy and records the update. Nothing happens when
   * the change leaves every visible field as it was (a no-op patch).
   */
  finishUpdate<K extends MetaKind>(kind: K, before: KindTypes[K], after: KindTypes[K]): boolean {
    const fields = diffObjects(objectOf(kind, before), objectOf(kind, after));
    if (fields.length === 0) return false;
    this.put(kind, after);
    this.record(kind, "update", before, after);
    return true;
  }

  /** Soft-deletes an object. */
  softDelete<K extends MetaKind>(kind: K, before: KindTypes[K], derived = false): void {
    const after = structuredClone(before);
    const meta = (after as { meta: Meta }).meta;
    meta.deleted = this.stamp();
    meta.updated = this.stamp();
    this.put(kind, after);
    this.record(kind, "delete", before, after, derived);
  }

  /** Brings an object back; `after` is the object as restored (its `meta.deleted` is cleared). */
  undelete<K extends MetaKind>(kind: K, before: KindTypes[K], after: KindTypes[K], derived = false): void {
    const meta = (after as { meta: Meta }).meta;
    meta.deleted = null;
    meta.updated = this.stamp();
    this.put(kind, after);
    this.record(kind, "restore", before, after, derived);
  }

  checkTransition(kind: Kind, id: string, from: Status, to: Status): void {
    if (statusTransitionAllowed(from, to)) return;
    throw new Problem("ipam.status.transition", {
      status: 409,
      detail: `${kind} ${id} cannot change status from ${from} to ${to}`,
      params: { from, to },
      errors: [fieldError("status", "ipam.status.transition")],
    });
  }

  /** Warns when a live child is active inside a planned or deprecated parent. */
  checkParentStatus(child: ObjectRef, status: Status, parent: ObjectRef, parentStatus: Status): void {
    if (status === "active" && (parentStatus === "deprecated" || parentStatus === "planned")) {
      this.warn(
        "ipam.parent_status",
        `${child.kind} ${child.id} is active inside ${parent.kind} ${parent.id}, which is ${parentStatus}`,
        child,
        { parent: `${parent.kind} ${parent.id}`, parent_status: parentStatus },
      );
    }
  }

  // ---- hosts, interfaces and ranges, shared by the space and host rules ----------------

  /** Fails with `ipam.host.locked` when automation touches a locked host (IPAM-16). */
  checkUnlocked(host: Host): void {
    if (host.lock && this.automation) {
      throw new Problem("ipam.host.locked", {
        status: 423,
        detail: `host ${host.name} is locked against automation`,
        params: { host: host.name },
      });
    }
  }

  interfacesOf(host: string, withDeleted = false): Interface[] {
    const out: Interface[] = [];
    for (const item of this.data.interface.values()) {
      if (item.host === host && (withDeleted || !item.meta.deleted)) out.push(item);
    }
    return out;
  }

  addressesOfInterface(interfaceId: string, withDeleted = false): Address[] {
    const out: Address[] = [];
    for (const item of this.data.address.values()) {
      if (item.interface === interfaceId && (withDeleted || !item.meta.deleted)) out.push(item);
    }
    return out;
  }

  rangesOf(prefix: string, withDeleted = false): Range[] {
    const out: Range[] = [];
    for (const item of this.data.range.values()) {
      if (item.prefix === prefix && (withDeleted || !item.meta.deleted)) out.push(item);
    }
    return out;
  }

  /** The host an address is assigned to, if any. */
  hostOfAddress(address: Address): Host | undefined {
    const iface = address.interface ? this.data.interface.get(address.interface) : undefined;
    return iface ? this.data.host.get(iface.host) : undefined;
  }

  /** The DHCP pool rule of IPAM-23 for one address. */
  checkPool(prefix: Prefix, ip: string, mode: AssignmentMode | undefined, object: ObjectRef): void {
    const value = ipOf(ip);
    for (const range of this.rangesOf(prefix.id)) {
      const first = ipOf(range.first);
      const last = ipOf(range.last);
      if (first.version !== value.version || value.value < first.value || value.value > last.value) continue;
      const label = `${range.first}-${range.last}`;
      if (range.role === "dhcp_pool") {
        if (mode === "reserved") {
          throw new Problem("ipam.address.in_dhcp_pool", {
            status: 409,
            detail: `${ip} is a reservation inside the DHCP pool ${label}`,
            params: { ip, range: label },
            errors: [fieldError("ip", "ipam.address.in_dhcp_pool")],
          });
        }
        this.warn("ipam.address.in_dhcp_pool", `${ip} lies inside the DHCP pool ${label}`, object, { ip, range: label });
      } else if (range.role === "reserved") {
        this.warn("ipam.address.in_range", `${ip} lies inside the reserved range ${label}`, object, { ip, range: label });
      }
    }
  }
}
