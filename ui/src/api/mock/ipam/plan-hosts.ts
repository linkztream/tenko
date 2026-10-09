// Hosts and interfaces (IPAM-08, IPAM-12, IPAM-14, IPAM-16, IPAM-18): the rules of
// crates/tenko-ipam/src/plan/planner/hosts.rs.
//
// A locked host refuses changes from automation (`ipam.host.locked`, 423) and only people
// lock and unlock it. A `reserved` host needs a MAC (for IPv4) or a DUID (for IPv6) on an
// interface before a reservation can be created; the plan warns when one is missing.
import type { AssignmentMode, Host, Interface, ObjectRef } from "../../types";
import { ASSIGNMENT_MODES } from "../../types";
import { Problem, fieldError } from "../reply";
import {
  Body,
  hexDigits,
  normalizeDnsName,
  normalizeMac,
  readMeta,
  readUpdate,
  type Json,
  type MetaInput,
} from "./input";
import { ipOf } from "./net";
import { defaultTenant } from "./plan-tenancy";
import { deleteAddress, restoreAddress } from "./plan-space";
import { inUse } from "./problems";
import type { Workspace } from "./workspace";

function ref(kind: ObjectRef["kind"], id: string): ObjectRef {
  return { kind, id };
}

function lockManualOnly(): Problem {
  return new Problem("ipam.host.lock_manual_only", {
    status: 403,
    detail: "only people lock and unlock hosts",
    errors: [fieldError("lock", "ipam.host.lock_manual_only")],
  });
}

function readHostName(b: Body, key: string, required: boolean): string | undefined {
  if (b.missing(key)) {
    if (required) b.add(key, `${key} is required`);
    return undefined;
  }
  const raw = b.raw[key];
  const name = typeof raw === "string" ? normalizeDnsName(raw, 1) : null;
  if (name === null) {
    b.add(key, `${key} must be a host name such as nas01 or nas01.example.test`);
    return undefined;
  }
  return name;
}

// ---------------------------------------------------------------------------------
// Interfaces

interface InterfaceFields {
  id?: string | undefined;
  host?: string | undefined;
  name: string;
  mac?: string | null | undefined;
  duid?: string | null | undefined;
  clientId?: string | null | undefined;
  meta: MetaInput;
}

const INTERFACE_MEMBERS = ["client_id", "custom", "description", "duid", "host", "id", "mac", "name", "tags"] as const;

function readMac(b: Body, key: string): string | null | undefined {
  const raw = b.nullableString(key);
  if (raw === undefined || raw === null) return raw;
  const mac = normalizeMac(raw);
  if (mac === null) {
    b.add(key, `${key} must be a MAC address such as 00:00:5e:00:53:01`);
    return undefined;
  }
  return mac;
}

function readHex(b: Body, key: string, minBytes: number, maxBytes: number): string | null | undefined {
  const raw = b.nullableString(key);
  if (raw === undefined || raw === null) return raw;
  const hex = hexDigits(raw);
  if (hex === null || hex.length < minBytes * 2 || hex.length > maxBytes * 2) {
    b.add(key, `${key} must be ${minBytes} to ${maxBytes} bytes of hexadecimal`);
    return undefined;
  }
  return hex;
}

/** Reads an interface body (a new one when `create`, else a patch) without checking state. */
function readInterface(b: Body, create: boolean): InterfaceFields {
  const name = create ? b.reqName("name") : (b.name("name") ?? "");
  return {
    id: create ? b.uuid("id") : undefined,
    host: create ? b.uuid("host") : undefined,
    name,
    mac: readMac(b, "mac"),
    duid: readHex(b, "duid", 2, 130),
    clientId: readHex(b, "client_id", 1, 255),
    meta: readMeta(b),
  };
}

function checkInterfaceName(ws: Workspace, host: string, name: string, exclude?: string): void {
  const taken = ws
    .interfacesOf(host)
    .some((i) => i.id !== exclude && i.name.toLowerCase() === name.toLowerCase());
  if (taken) {
    throw new Problem("ipam.name_taken", {
      status: 409,
      detail: `an interface named ${name} exists already`,
      params: { kind: "interface", name },
      errors: [fieldError("name", "ipam.name_taken")],
    });
  }
}

/** Warns when another live interface has the MAC address. */
function checkMac(ws: Workspace, id: string, mac: string): void {
  const other = ws.find("interface", (i) => i.id !== id && i.mac === mac);
  if (other) {
    ws.warn(
      "ipam.interface.duplicate_mac",
      `MAC address ${mac} is also on interface ${other.id}`,
      ref("interface", id),
      { mac, other: other.id },
    );
  }
}

function insertInterface(ws: Workspace, hostId: string, input: InterfaceFields): Interface {
  const host = ws.liveRef("host", hostId, "host");
  ws.checkUnlocked(host);
  checkInterfaceName(ws, hostId, input.name);
  const id = ws.claimId("interface", input.id);
  if (input.mac) checkMac(ws, id, input.mac);
  const iface: Interface = {
    id,
    host: hostId,
    name: input.name,
    mac: input.mac ?? null,
    duid: input.duid ?? null,
    client_id: input.clientId ?? null,
    meta: ws.makeMeta("interface", input.meta),
  };
  ws.put("interface", iface);
  ws.record("interface", "create", null, iface);
  ws.reservationChecks.add(hostId);
  return iface;
}

export function createInterface(ws: Workspace, args: Json): ObjectRef {
  const b = new Body(args).only(INTERFACE_MEMBERS);
  const input = readInterface(b, true);
  b.done();
  if (!input.host) throw new Problem("ipam.validation", {
    status: 400,
    detail: "an interface needs a host",
    params: { field: "host" },
    errors: [fieldError("host", "ipam.validation")],
  });
  return ref("interface", insertInterface(ws, input.host, input).id);
}

export function updateInterface(ws: Workspace, args: Json): ObjectRef {
  const { id, expected, patch } = readUpdate(args, INTERFACE_MEMBERS.filter((m) => m !== "id" && m !== "host"));
  const fields = readInterface(patch, false);
  patch.done();
  const before = ws.loadForChange("interface", id, expected);
  const host = ws.liveRef("host", before.host, "host");
  ws.checkUnlocked(host);
  const after = structuredClone(before);
  if (fields.name !== "") {
    if (fields.name.toLowerCase() !== before.name.toLowerCase()) checkInterfaceName(ws, host.id, fields.name, id);
    after.name = fields.name;
  }
  if (fields.mac !== undefined) {
    if (fields.mac !== before.mac && fields.mac) checkMac(ws, id, fields.mac);
    after.mac = fields.mac;
  }
  if (fields.duid !== undefined) after.duid = fields.duid;
  if (fields.clientId !== undefined) after.client_id = fields.clientId;
  ws.patchMeta("interface", after.meta, fields.meta);
  ws.reservationChecks.add(host.id);
  ws.finishUpdate("interface", before, after);
  return ref("interface", id);
}

export function deleteInterface(
  ws: Workspace,
  id: string,
  expected: number | null,
  cascade: boolean,
  derived = false,
): ObjectRef {
  const before = ws.loadForChange("interface", id, expected);
  const host = ws.get("host", before.host);
  if (host) ws.checkUnlocked(host);
  const addresses = ws.addressesOfInterface(id);
  if (addresses.length > 0) {
    if (!cascade) throw inUse("interface", id, "addresses", addresses.length);
    for (const address of addresses) deleteAddress(ws, address.id, null, true);
  }
  ws.reservationChecks.add(before.host);
  ws.softDelete("interface", before, derived);
  return ref("interface", id);
}

export function restoreInterface(ws: Workspace, id: string, expected: number | null, derived = false): ObjectRef {
  const before = ws.loadForChange("interface", id, expected, true);
  ws.requireDeleted("interface", id, before.meta);
  const host = ws.liveRef("host", before.host, "host");
  ws.checkUnlocked(host);
  checkInterfaceName(ws, host.id, before.name, id);
  if (before.mac) checkMac(ws, id, before.mac);
  const together = JSON.stringify(before.meta.deleted);
  ws.undelete("interface", before, structuredClone(before), derived);
  for (const address of ws.addressesOfInterface(id, true)) {
    if (address.meta.deleted && JSON.stringify(address.meta.deleted) === together) {
      restoreAddress(ws, address.id, null, true);
    }
  }
  ws.reservationChecks.add(host.id);
  return ref("interface", id);
}

// ---------------------------------------------------------------------------------
// Hosts

/** A host that becomes `reserved` must not have an address inside a DHCP pool (IPAM-23). */
function checkHostPools(ws: Workspace, host: string): void {
  for (const iface of ws.interfacesOf(host)) {
    for (const address of ws.addressesOfInterface(iface.id)) {
      const prefix = ws.get("prefix", address.prefix);
      if (prefix) ws.checkPool(prefix, address.ip, "reserved", ref("address", address.id));
    }
  }
}

export function createHost(ws: Workspace, args: Json): ObjectRef {
  const b = new Body(args).only([
    "custom",
    "description",
    "id",
    "interfaces",
    "lock",
    "mode",
    "name",
    "site",
    "tags",
    "tenant",
  ]);
  const wanted = b.uuid("id");
  const name = readHostName(b, "name", true) ?? "";
  const tenant = b.uuid("tenant");
  const mode = b.oneOf<AssignmentMode>("mode", ASSIGNMENT_MODES);
  const lock = b.bool("lock");
  const site = b.uuid("site");
  const meta = readMeta(b);
  const inline = b.objects("interfaces") ?? [];
  const interfaces = inline.map((raw, index) => {
    const child = new Body(raw, `interfaces[${index}].`).only(INTERFACE_MEMBERS);
    const fields = readInterface(child, true);
    b.absorb(child);
    return fields;
  });
  b.done();
  const tenantId = tenant ?? defaultTenant(ws);
  ws.liveRef("tenant", tenantId, "tenant");
  const id = ws.claimId("host", wanted);
  ws.assertFree("host", "host", name, (h) => h.tenant === tenantId && h.name === name);
  if (site) ws.liveRef("site", site, "site");
  const host: Host = {
    id,
    tenant: tenantId,
    name,
    mode: mode ?? "static",
    lock: lock ?? false,
    site: site ?? null,
    meta: ws.makeMeta("host", meta),
  };
  ws.put("host", host);
  ws.record("host", "create", null, host);
  interfaces.forEach((fields, index) => {
    if (fields.host !== undefined && fields.host !== id) {
      throw new Problem("ipam.validation", {
        status: 400,
        detail: "an interface listed with a host belongs to that host",
        params: { field: `interfaces[${index}].host` },
        errors: [fieldError(`interfaces[${index}].host`, "ipam.validation")],
      });
    }
    insertInterface(ws, id, fields);
  });
  ws.reservationChecks.add(id);
  return ref("host", id);
}

export function updateHost(ws: Workspace, args: Json): ObjectRef {
  const { id, expected, patch } = readUpdate(args, [
    "custom",
    "description",
    "lock",
    "mode",
    "name",
    "site",
    "tags",
  ]);
  const name = readHostName(patch, "name", false);
  const mode = patch.oneOf<AssignmentMode>("mode", ASSIGNMENT_MODES);
  const lock = patch.bool("lock");
  const site = patch.nullUuid("site");
  const meta = readMeta(patch);
  patch.done();
  const before = ws.loadForChange("host", id, expected);
  ws.checkUnlocked(before);
  const after = structuredClone(before);
  if (name !== undefined && name !== before.name) {
    ws.assertFree("host", "host", name, (h) => h.tenant === before.tenant && h.name === name, id);
    after.name = name;
  }
  if (mode !== undefined) {
    if (mode === "reserved" && before.mode !== "reserved") checkHostPools(ws, id);
    after.mode = mode;
  }
  if (lock !== undefined && lock !== before.lock) {
    if (ws.automation) throw lockManualOnly();
    after.lock = lock;
  }
  if (site !== undefined) {
    if (site !== null && site !== before.site) ws.liveRef("site", site, "site");
    after.site = site;
  }
  ws.patchMeta("host", after.meta, meta);
  ws.reservationChecks.add(id);
  ws.finishUpdate("host", before, after);
  return ref("host", id);
}

export function setLock(ws: Workspace, args: Json): ObjectRef {
  const b = new Body(args).only(["expected", "host", "lock"]);
  const id = b.reqUuid("host");
  const lock = b.bool("lock");
  if (lock === undefined) b.add("lock", "lock is required");
  const expected = b.expected();
  b.done();
  if (ws.automation) throw lockManualOnly();
  const before = ws.loadForChange("host", id, expected);
  if (before.lock === lock) return ref("host", id);
  const after = structuredClone(before);
  after.lock = lock === true;
  after.meta.updated = ws.stamp();
  ws.put("host", after);
  ws.record("host", lock ? "lock" : "unlock", before, after);
  return ref("host", id);
}

export function setMode(ws: Workspace, args: Json): ObjectRef {
  const b = new Body(args).only(["expected", "host", "mode"]);
  const id = b.reqUuid("host");
  const mode = b.reqOneOf<AssignmentMode>("mode", ASSIGNMENT_MODES);
  const expected = b.expected();
  b.done();
  const before = ws.loadForChange("host", id, expected);
  ws.checkUnlocked(before);
  if (mode === "reserved" && before.mode !== "reserved") checkHostPools(ws, id);
  const after = structuredClone(before);
  after.mode = mode;
  after.meta.updated = ws.stamp();
  ws.reservationChecks.add(id);
  ws.finishUpdate("host", before, after);
  return ref("host", id);
}

export function deleteHost(ws: Workspace, id: string, expected: number | null, cascade: boolean): ObjectRef {
  const before = ws.loadForChange("host", id, expected);
  ws.checkUnlocked(before);
  const interfaces = ws.interfacesOf(id);
  if (!cascade) {
    let addresses = 0;
    for (const iface of interfaces) addresses += ws.addressesOfInterface(iface.id).length;
    if (addresses > 0) throw inUse("host", id, "addresses", addresses);
  }
  for (const iface of interfaces) deleteInterface(ws, iface.id, null, cascade, true);
  ws.reservationChecks.delete(id);
  ws.softDelete("host", before);
  return ref("host", id);
}

export function restoreHost(ws: Workspace, id: string, expected: number | null): ObjectRef {
  const before = ws.loadForChange("host", id, expected, true);
  ws.requireDeleted("host", id, before.meta);
  ws.liveRef("tenant", before.tenant, "tenant");
  if (before.site) ws.liveRef("site", before.site, "site");
  ws.assertFree("host", "host", before.name, (h) => h.tenant === before.tenant && h.name === before.name, id);
  const together = JSON.stringify(before.meta.deleted);
  ws.undelete("host", before, structuredClone(before));
  for (const iface of ws.interfacesOf(id, true)) {
    if (iface.meta.deleted && JSON.stringify(iface.meta.deleted) === together) restoreInterface(ws, iface.id, null, true);
  }
  ws.reservationChecks.add(id);
  return ref("host", id);
}

// ---------------------------------------------------------------------------------
// IPAM-18

/**
 * Warns for every touched `reserved` host that lacks the identifier a reservation needs: a
 * MAC (or client identifier) for IPv4, a DUID for IPv6.
 */
export function checkReservations(ws: Workspace): void {
  const hosts = [...ws.reservationChecks];
  ws.reservationChecks.clear();
  for (const id of hosts) {
    const host = ws.get("host", id);
    if (!host || host.meta.deleted || host.mode !== "reserved") continue;
    let hasMac = false;
    let hasDuid = false;
    const families = new Set<4 | 6>();
    for (const iface of ws.interfacesOf(id)) {
      hasMac ||= iface.mac != null || iface.client_id != null;
      hasDuid ||= iface.duid != null;
      for (const address of ws.addressesOfInterface(iface.id)) families.add(ipOf(address.ip).version);
    }
    const needsMac = families.has(4) && !hasMac;
    const needsDuid = families.has(6) && !hasDuid;
    const needsAny = families.size === 0 && !hasMac && !hasDuid;
    if (!needsMac && !needsDuid && !needsAny) continue;
    const missing =
      needsMac && needsDuid ? "MAC address and DUID" : needsMac ? "MAC address" : needsDuid ? "DUID" : "MAC address or DUID";
    ws.warn(
      "ipam.host.reservation_identifier",
      `host ${host.name} is reserved but has no ${missing} for its reservation`,
      ref("host", id),
      { host: host.name, missing },
    );
  }
}
