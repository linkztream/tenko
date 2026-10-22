// Tenants, VRFs, sites, VLANs and custom field definitions (IPAM-01, IPAM-03, IPAM-04,
// IPAM-08): the rules of crates/tenko-ipam/src/plan/planner/{tenancy,fields}.rs.
import type { CustomFieldDef, CustomKind, ObjectRef, Site, Status, Tenant, Vlan, Vrf } from "../../types";
import { STATUSES } from "../../types";
import { Problem, fieldError } from "../reply";
import { dnsState } from "../routes-dns";
import { Body, isJson, readMeta, readUpdate, type Json, type MetaInput } from "./input";
import { inUse, nameTaken, notFound, revisionMismatch } from "./problems";
import { META_KINDS, type MetaKind } from "./state";
import type { Workspace } from "./workspace";

const DEFAULT_NAME = "default";
const MAX_VNI = 0x00ff_ffff;

function same(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

// ---------------------------------------------------------------------------------
// Tenants

function insertTenant(ws: Workspace, wanted: string | undefined, name: string, meta: MetaInput, derived: boolean): Tenant {
  const id = ws.claimId("tenant", wanted);
  ws.assertFree("tenant", "tenant", name, (t) => same(t.name, name));
  const tenant: Tenant = { id, name, meta: ws.makeMeta("tenant", meta) };
  ws.put("tenant", tenant);
  ws.record("tenant", "create", null, tenant, derived);
  return tenant;
}

/** The tenant `default`, created on first use. */
export function defaultTenant(ws: Workspace): string {
  if (ws.defaultTenantId) return ws.defaultTenantId;
  const found = ws.find("tenant", (t) => same(t.name, DEFAULT_NAME));
  const id = found?.id ?? insertTenant(ws, undefined, DEFAULT_NAME, { description: "Created on first use" }, true).id;
  ws.defaultTenantId = id;
  return id;
}

export function createTenant(ws: Workspace, args: Json): ObjectRef {
  const b = new Body(args).only(["custom", "description", "id", "name", "tags"]);
  const id = b.uuid("id");
  const name = b.reqName("name");
  const meta = readMeta(b);
  b.done();
  return { kind: "tenant", id: insertTenant(ws, id, name, meta, false).id };
}

/**
 * `dns` of a tenant patch: absent leaves it, `{}` and `null` clear it, `{ default_zone }` sets
 * the default zone. Returns the zone to set (null to clear), or undefined for no change.
 */
function readTenantDns(patch: Body): { zone: string | null } | undefined {
  const raw = patch.raw.dns;
  if (raw === undefined) return undefined;
  if (raw === null) return { zone: null };
  if (!isJson(raw)) {
    patch.add("dns", "dns must be an object");
    return undefined;
  }
  const dns = new Body(raw, "dns.").only(["default_zone"]);
  const zone = dns.nullUuid("default_zone");
  patch.absorb(dns);
  return { zone: zone ?? null };
}

/** The zone must be a primary forward zone of the tenant or one without a tenant (`dns.default_zone.invalid`). */
function checkDefaultZone(tenant: string, zone: string): void {
  const found = dnsState().zones.find((z) => z.id === zone);
  const reason = !found
    ? "missing"
    : found.kind !== "primary"
      ? "not_primary"
      : found.name === "arpa" || found.name.endsWith(".arpa")
        ? "reverse"
        : found.tenant && found.tenant !== tenant
          ? "other_tenant"
          : null;
  if (reason === null) return;
  throw new Problem("dns.default_zone.invalid", {
    status: 409,
    detail: `${found?.name ?? zone} cannot be the default zone of the tenant (${reason}): it must be a primary forward zone of the tenant or one without a tenant`,
    params: { zone, reason },
    errors: [fieldError("dns.default_zone", "dns.default_zone.invalid")],
  });
}

export function updateTenant(ws: Workspace, args: Json): ObjectRef {
  const { id, expected, patch } = readUpdate(args, ["custom", "description", "dns", "name", "tags"]);
  const name = patch.name("name");
  const dns = readTenantDns(patch);
  const meta = readMeta(patch);
  patch.done();
  const before = ws.loadForChange("tenant", id, expected);
  const after = structuredClone(before);
  if (name !== undefined) {
    if (!same(name, before.name)) ws.assertFree("tenant", "tenant", name, (t) => same(t.name, name), id);
    after.name = name;
  }
  if (dns !== undefined) {
    if (dns.zone !== null && dns.zone !== before.dns?.default_zone) checkDefaultZone(id, dns.zone);
    if (dns.zone === null) delete after.dns;
    else after.dns = { default_zone: dns.zone };
  }
  ws.patchMeta("tenant", after.meta, meta);
  ws.finishUpdate("tenant", before, after);
  return { kind: "tenant", id };
}

export function deleteTenant(ws: Workspace, id: string, expected: number | null): ObjectRef {
  const before = ws.loadForChange("tenant", id, expected);
  const vrfs = ws.live("vrf").filter((v) => v.tenant === id).length;
  if (vrfs > 0) throw inUse("tenant", id, "VRFs", vrfs);
  const hosts = ws.live("host").filter((h) => h.tenant === id).length;
  if (hosts > 0) throw inUse("tenant", id, "hosts", hosts);
  ws.softDelete("tenant", before);
  if (ws.defaultTenantId === id) ws.defaultTenantId = null;
  return { kind: "tenant", id };
}

export function restoreTenant(ws: Workspace, id: string, expected: number | null): ObjectRef {
  const before = ws.loadForChange("tenant", id, expected, true);
  ws.requireDeleted("tenant", id, before.meta);
  ws.assertFree("tenant", "tenant", before.name, (t) => same(t.name, before.name), id);
  ws.undelete("tenant", before, structuredClone(before));
  return { kind: "tenant", id };
}

// ---------------------------------------------------------------------------------
// VRFs

function insertVrf(
  ws: Workspace,
  wanted: string | undefined,
  tenantId: string,
  name: string,
  rd: string | null,
  meta: MetaInput,
  derived: boolean,
): Vrf {
  ws.liveRef("tenant", tenantId, "tenant");
  const id = ws.claimId("vrf", wanted);
  ws.assertFree("vrf", "VRF", name, (v) => v.tenant === tenantId && same(v.name, name));
  const vrf: Vrf = { id, tenant: tenantId, name, rd, meta: ws.makeMeta("vrf", meta) };
  ws.put("vrf", vrf);
  ws.record("vrf", "create", null, vrf, derived);
  return vrf;
}

/** The VRF `default` of the default tenant, created on first use. */
export function defaultVrf(ws: Workspace): string {
  if (ws.defaultVrfId) return ws.defaultVrfId;
  const tenant = defaultTenant(ws);
  const found = ws.find("vrf", (v) => v.tenant === tenant && same(v.name, DEFAULT_NAME));
  const id =
    found?.id ?? insertVrf(ws, undefined, tenant, DEFAULT_NAME, null, { description: "Created on first use" }, true).id;
  ws.defaultVrfId = id;
  return id;
}

export function createVrf(ws: Workspace, args: Json): ObjectRef {
  const b = new Body(args).only(["custom", "description", "id", "name", "rd", "tags", "tenant"]);
  const id = b.uuid("id");
  const tenant = b.uuid("tenant");
  const name = b.reqName("name");
  const rd = b.clearable("rd");
  const meta = readMeta(b);
  b.done();
  const tenantId = tenant ?? defaultTenant(ws);
  return { kind: "vrf", id: insertVrf(ws, id, tenantId, name, rd ?? null, meta, false).id };
}

export function updateVrf(ws: Workspace, args: Json): ObjectRef {
  const { id, expected, patch } = readUpdate(args, ["custom", "description", "name", "rd", "tags"]);
  const name = patch.name("name");
  const rd = patch.clearable("rd");
  const meta = readMeta(patch);
  patch.done();
  const before = ws.loadForChange("vrf", id, expected);
  const after = structuredClone(before);
  if (name !== undefined) {
    if (!same(name, before.name)) {
      ws.assertFree("vrf", "VRF", name, (v) => v.tenant === before.tenant && same(v.name, name), id);
    }
    after.name = name;
  }
  if (rd !== undefined) after.rd = rd;
  ws.patchMeta("vrf", after.meta, meta);
  ws.finishUpdate("vrf", before, after);
  return { kind: "vrf", id };
}

export function deleteVrf(ws: Workspace, id: string, expected: number | null): ObjectRef {
  const before = ws.loadForChange("vrf", id, expected);
  const prefixes = ws.live("prefix").filter((p) => p.vrf === id).length;
  if (prefixes > 0) throw inUse("vrf", id, "prefixes", prefixes);
  ws.softDelete("vrf", before);
  if (ws.defaultVrfId === id) ws.defaultVrfId = null;
  return { kind: "vrf", id };
}

export function restoreVrf(ws: Workspace, id: string, expected: number | null): ObjectRef {
  const before = ws.loadForChange("vrf", id, expected, true);
  ws.requireDeleted("vrf", id, before.meta);
  ws.liveRef("tenant", before.tenant, "tenant");
  ws.assertFree("vrf", "VRF", before.name, (v) => v.tenant === before.tenant && same(v.name, before.name), id);
  ws.undelete("vrf", before, structuredClone(before));
  return { kind: "vrf", id };
}

// ---------------------------------------------------------------------------------
// Sites

export function createSite(ws: Workspace, args: Json): ObjectRef {
  const b = new Body(args).only(["ad_site", "custom", "description", "id", "name", "parent", "tags"]);
  const wanted = b.uuid("id");
  const name = b.reqName("name");
  const parent = b.uuid("parent");
  const adSite = b.clearable("ad_site");
  const meta = readMeta(b);
  b.done();
  const id = ws.claimId("site", wanted);
  ws.assertFree("site", "site", name, (s) => same(s.name, name));
  if (parent) ws.liveRef("site", parent, "parent");
  const site: Site = { id, name, parent: parent ?? null, ad_site: adSite ?? null, meta: ws.makeMeta("site", meta) };
  ws.put("site", site);
  ws.record("site", "create", null, site);
  return { kind: "site", id };
}

function checkSiteCycle(ws: Workspace, site: string, parent: string): void {
  let cursor: string | null = parent;
  for (let steps = 0; cursor !== null; steps += 1) {
    if (cursor === site || steps > 64) {
      throw new Problem("ipam.site.cycle", {
        status: 409,
        detail: "a site cannot be nested inside itself",
        errors: [fieldError("parent", "ipam.site.cycle")],
      });
    }
    cursor = ws.get("site", cursor)?.parent ?? null;
  }
}

export function updateSite(ws: Workspace, args: Json): ObjectRef {
  const { id, expected, patch } = readUpdate(args, ["ad_site", "custom", "description", "name", "parent", "tags"]);
  const name = patch.name("name");
  const parent = patch.nullUuid("parent");
  const adSite = patch.clearable("ad_site");
  const meta = readMeta(patch);
  patch.done();
  const before = ws.loadForChange("site", id, expected);
  const after = structuredClone(before);
  if (name !== undefined) {
    if (!same(name, before.name)) ws.assertFree("site", "site", name, (s) => same(s.name, name), id);
    after.name = name;
  }
  if (parent !== undefined) {
    if (parent !== null && parent !== before.parent) {
      ws.liveRef("site", parent, "parent");
      checkSiteCycle(ws, id, parent);
    }
    after.parent = parent;
  }
  if (adSite !== undefined) after.ad_site = adSite;
  ws.patchMeta("site", after.meta, meta);
  ws.finishUpdate("site", before, after);
  return { kind: "site", id };
}

export function deleteSite(ws: Workspace, id: string, expected: number | null): ObjectRef {
  const before = ws.loadForChange("site", id, expected);
  const counts: [string, number][] = [
    ["sites", ws.live("site").filter((s) => s.parent === id).length],
    ["VLANs", ws.live("vlan").filter((v) => v.site === id).length],
    ["prefixes", ws.live("prefix").filter((p) => p.site === id).length],
    ["hosts", ws.live("host").filter((h) => h.site === id).length],
  ];
  for (const [by, count] of counts) if (count > 0) throw inUse("site", id, by, count);
  ws.softDelete("site", before);
  return { kind: "site", id };
}

export function restoreSite(ws: Workspace, id: string, expected: number | null): ObjectRef {
  const before = ws.loadForChange("site", id, expected, true);
  ws.requireDeleted("site", id, before.meta);
  if (before.parent) ws.liveRef("site", before.parent, "parent");
  ws.assertFree("site", "site", before.name, (s) => same(s.name, before.name), id);
  ws.undelete("site", before, structuredClone(before));
  return { kind: "site", id };
}

// ---------------------------------------------------------------------------------
// VLANs

function claimVid(ws: Workspace, site: string | null, vid: number, exclude?: string): void {
  const other = ws.find("vlan", (v) => v.id !== exclude && (v.site ?? null) === site && v.vid === vid);
  if (other) {
    throw new Problem("ipam.vlan.duplicate", {
      status: 409,
      detail: `VLAN ${vid} exists already at this site`,
      params: { vid: String(vid) },
      errors: [fieldError("vid", "ipam.vlan.duplicate")],
    });
  }
}

export function createVlan(ws: Workspace, args: Json): ObjectRef {
  const b = new Body(args).only(["custom", "description", "id", "name", "site", "status", "tags", "vid", "vni"]);
  const wanted = b.uuid("id");
  const vid = b.reqInteger("vid", 1, 4094);
  const vni = b.nullableInteger("vni", 0, MAX_VNI);
  const name = b.reqName("name");
  const site = b.uuid("site");
  const status = b.oneOf<Status>("status", STATUSES);
  const meta = readMeta(b);
  b.done();
  const id = ws.claimId("vlan", wanted);
  if (site) ws.liveRef("site", site, "site");
  claimVid(ws, site ?? null, vid);
  const vlan: Vlan = {
    id,
    vid,
    vni: vni ?? null,
    name,
    site: site ?? null,
    status: status ?? "active",
    meta: ws.makeMeta("vlan", meta),
  };
  ws.put("vlan", vlan);
  ws.record("vlan", "create", null, vlan);
  return { kind: "vlan", id };
}

export function updateVlan(ws: Workspace, args: Json): ObjectRef {
  const { id, expected, patch } = readUpdate(args, [
    "custom",
    "description",
    "name",
    "site",
    "status",
    "tags",
    "vid",
    "vni",
  ]);
  const vid = patch.integer("vid", 1, 4094);
  const vni = patch.nullableInteger("vni", 0, MAX_VNI);
  const name = patch.name("name");
  const site = patch.nullUuid("site");
  const status = patch.oneOf<Status>("status", STATUSES);
  const meta = readMeta(patch);
  patch.done();
  const before = ws.loadForChange("vlan", id, expected);
  const after = structuredClone(before);
  if (vid !== undefined) after.vid = vid;
  if (vni !== undefined) after.vni = vni;
  if (name !== undefined) after.name = name;
  if (site !== undefined) {
    if (site !== null && site !== before.site) ws.liveRef("site", site, "site");
    after.site = site;
  }
  if ((after.site ?? null) !== (before.site ?? null) || after.vid !== before.vid) {
    claimVid(ws, after.site ?? null, after.vid, id);
  }
  if (status !== undefined) {
    ws.checkTransition("vlan", id, before.status, status);
    after.status = status;
  }
  ws.patchMeta("vlan", after.meta, meta);
  ws.finishUpdate("vlan", before, after);
  return { kind: "vlan", id };
}

export function deleteVlan(ws: Workspace, id: string, expected: number | null): ObjectRef {
  const before = ws.loadForChange("vlan", id, expected);
  const prefixes = ws.live("prefix").filter((p) => p.vlan === id).length;
  if (prefixes > 0) throw inUse("vlan", id, "prefixes", prefixes);
  ws.softDelete("vlan", before);
  return { kind: "vlan", id };
}

export function restoreVlan(ws: Workspace, id: string, expected: number | null): ObjectRef {
  const before = ws.loadForChange("vlan", id, expected, true);
  ws.requireDeleted("vlan", id, before.meta);
  if (before.site) ws.liveRef("site", before.site, "site");
  claimVid(ws, before.site ?? null, before.vid, id);
  ws.undelete("vlan", before, structuredClone(before));
  return { kind: "vlan", id };
}

// ---------------------------------------------------------------------------------
// Custom field definitions

const FIELD_KEY = /^[a-z][a-z0-9_]{0,63}$/;
const KIND_TYPES = ["text", "integer", "boolean", "date", "url", "select"] as const;

function readKind(b: Body, key: string): CustomKind | undefined {
  const raw = b.raw[key];
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== "object" || Array.isArray(raw)) {
    b.add(key, `${key} must be an object with a type`);
    return undefined;
  }
  const inner = new Body(raw as Json, `${key}.`);
  const type = inner.reqOneOf("type", KIND_TYPES);
  let kind: CustomKind | undefined;
  if (type === "select") {
    inner.only(["options", "type"]);
    const options = (raw as Json).options;
    if (!Array.isArray(options) || !options.every((o) => typeof o === "string")) {
      inner.add("options", "options must be a list of texts");
    } else {
      kind = { type: "select", options: options as string[] };
    }
  } else {
    inner.only(["type"]);
    kind = { type } as CustomKind;
  }
  b.absorb(inner);
  return kind;
}

/** What is wrong with a definition, or null. */
function definitionProblem(def: CustomFieldDef): string | null {
  if (def.applies_to.length === 0) return "applies_to must name at least one object kind";
  for (const [index, kind] of def.applies_to.entries()) {
    if (!(META_KINDS as readonly string[]).includes(kind)) return `a custom field cannot apply to ${kind}`;
    if (def.applies_to.indexOf(kind) !== index) return `applies_to lists ${kind} more than once`;
  }
  if (def.kind.type === "select") {
    const options = def.kind.options;
    if (options.length === 0) return "a select needs at least one option";
    for (const [index, option] of options.entries()) {
      if (option.trim() === "" || Array.from(option).length > 128) return "an option must be 1 to 128 characters";
      if (options.indexOf(option) !== index) return `option ${option} is listed more than once`;
    }
  }
  return null;
}

function checkDefinition(def: CustomFieldDef): void {
  const message = definitionProblem(def);
  if (message) {
    throw new Problem("ipam.custom_field.invalid_definition", {
      status: 400,
      detail: message,
      params: { key: def.key },
      errors: [fieldError("definition", "ipam.custom_field.invalid_definition")],
    });
  }
}

function appliesTo(b: Body, key: string): MetaKind[] | undefined {
  if (b.missing(key)) return undefined;
  const raw = b.raw[key];
  if (!Array.isArray(raw) || !raw.every((v) => typeof v === "string")) {
    b.add(key, `${key} must be a list of object kinds`);
    return undefined;
  }
  return raw as MetaKind[];
}

function fieldNotFound(key: string): Problem {
  return new Problem("ipam.not_found", {
    status: 404,
    detail: `custom field ${key} does not exist`,
    params: { kind: "custom_field", key },
  });
}

function fieldByKey(ws: Workspace, key: string): CustomFieldDef {
  const found = [...ws.data.custom_field.values()].find((d) => d.key === key);
  if (!found) throw fieldNotFound(key);
  return found;
}

function fieldUses(ws: Workspace, key: string): number {
  let count = 0;
  for (const kind of META_KINDS) {
    for (const object of ws.map(kind).values()) {
      if (key in ((object as { meta: { custom?: Record<string, unknown> } }).meta.custom ?? {})) count += 1;
    }
  }
  return count;
}

function checkExpectedField(ws: Workspace, def: CustomFieldDef, expected: number | null): void {
  const actual = ws.data.fieldRevisions.get(def.id) ?? 0;
  if (expected !== null && expected !== actual) throw revisionMismatch("custom_field", def.id, expected, actual);
}

export function createCustomField(ws: Workspace, args: Json): ObjectRef {
  const b = new Body(args).only(["applies_to", "id", "key", "kind", "required"]);
  const wanted = b.uuid("id");
  const key = b.reqString("key");
  if (key !== "" && !FIELD_KEY.test(key)) b.add("key", "a key is a lowercase letter followed by letters, digits or underscores");
  const kind = readKind(b, "kind");
  if (b.missing("kind")) b.add("kind", "kind is required");
  const applies = appliesTo(b, "applies_to");
  if (b.missing("applies_to")) b.add("applies_to", "applies_to is required");
  const required = b.bool("required") ?? false;
  b.done();
  if (!kind || !applies) throw new Error("unreachable");
  const id = ws.claimId("custom_field", wanted);
  if ([...ws.data.custom_field.values()].some((d) => d.key === key)) throw nameTaken("custom field", key);
  const def: CustomFieldDef = { id, key, kind, applies_to: applies, required };
  checkDefinition(def);
  ws.put("custom_field", def);
  ws.data.fieldRevisions.set(id, 0);
  ws.record("custom_field", "create", null, def);
  return { kind: "custom_field", id };
}

export function updateCustomField(ws: Workspace, args: Json): ObjectRef {
  const outer = new Body(args).only(["expected", "key", "patch"]);
  const key = outer.reqString("key");
  const expected = outer.expected();
  const rawPatch = outer.reqObject("patch");
  outer.done();
  const patch = new Body(rawPatch).only(["applies_to", "kind", "required"]);
  const kind = readKind(patch, "kind");
  const applies = appliesTo(patch, "applies_to");
  const required = patch.bool("required");
  patch.done();
  const before = fieldByKey(ws, key);
  checkExpectedField(ws, before, expected);
  const after = structuredClone(before);
  if (kind && JSON.stringify(kind) !== JSON.stringify(before.kind)) {
    if (fieldUses(ws, key) > 0) {
      const lost =
        before.kind.type === "select" && kind.type === "select"
          ? before.kind.options.filter((o) => !kind.options.includes(o))
          : null;
      if (lost === null ? before.kind.type !== kind.type : lost.length > 0) {
        throw new Problem("ipam.custom_field.incompatible_change", {
          status: 409,
          detail:
            lost !== null
              ? `custom field ${key} cannot lose select options: ${lost.join(", ")}`
              : `custom field ${key} cannot change from ${before.kind.type} to ${kind.type}`,
          params: { key },
          errors: [fieldError("kind", "ipam.custom_field.incompatible_change")],
        });
      }
    }
    after.kind = kind;
  }
  if (applies) after.applies_to = applies;
  if (required !== undefined) after.required = required;
  if (JSON.stringify(after) === JSON.stringify(before)) return { kind: "custom_field", id: before.id };
  checkDefinition(after);
  ws.put("custom_field", after);
  ws.record("custom_field", "update", before, after);
  return { kind: "custom_field", id: before.id };
}

export function deleteCustomField(ws: Workspace, key: string, expected: number | null): ObjectRef {
  const before = fieldByKey(ws, key);
  checkExpectedField(ws, before, expected);
  const uses = fieldUses(ws, key);
  if (uses > 0) throw inUse("custom_field", before.id, "objects", uses);
  ws.data.custom_field.delete(before.id);
  ws.data.fieldRevisions.delete(before.id);
  ws.record("custom_field", "remove", before, null);
  return { kind: "custom_field", id: before.id };
}

/** A custom field definition by identifier, for the generic delete command. */
export function customFieldKeyOf(ws: Workspace, id: string): string {
  const found = ws.data.custom_field.get(id);
  if (!found) throw notFound("custom_field", id);
  return found.key;
}
