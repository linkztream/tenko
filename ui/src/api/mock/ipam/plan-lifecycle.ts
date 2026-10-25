// The lifecycle of a host (crates/tenko-ipam/src/plan/planner/lifecycle.rs): decommission
// releases the addresses of the host (unassigned, and their DNS names removed unless the
// caller keeps them) and records what it released on the host, reinstate binds the released
// addresses that are still free again and warns for each one that did not come back.
import type { Address, Host, ObjectRef, ReleasedAddress } from "../../types";
import { Problem, fieldError } from "../reply";
import { Body, type Json } from "./input";
import type { Workspace } from "./workspace";

const MAX_REASON_BYTES = 1024;
// eslint-disable-next-line no-control-regex -- control characters other than line breaks and tabs are refused
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

function ref(kind: ObjectRef["kind"], id: string): ObjectRef {
  return { kind, id };
}

/** The reason as it is recorded: trimmed, null for none; refused when too long. */
function readReason(b: Body): string | null {
  const raw = b.raw.reason;
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== "string") {
    b.add("reason", "reason must be a text or null");
    return null;
  }
  const reason = raw.trim();
  if (new TextEncoder().encode(reason).length > MAX_REASON_BYTES || CONTROL.test(reason)) {
    b.add("reason", "the reason has at most 1,024 bytes and no control characters other than line breaks and tabs");
    return null;
  }
  return reason === "" ? null : reason;
}

export function decommissionHost(ws: Workspace, args: Json): ObjectRef {
  const b = new Body(args).only(["expected", "host", "keep_dns", "reason"]);
  const id = b.reqUuid("host");
  const keepDns = b.bool("keep_dns") ?? false;
  const reason = readReason(b);
  const expected = b.expected();
  b.done();
  const before = ws.loadForChange("host", id, expected);
  ws.checkUnlocked(before);
  if (before.decommissioned) {
    throw new Problem("ipam.host.decommissioned", {
      status: 409,
      detail: `host ${before.name} is decommissioned already`,
      params: { host: before.name },
    });
  }
  const released: ReleasedAddress[] = [];
  for (const iface of ws.interfacesOf(id)) {
    for (const address of ws.addressesOfInterface(iface.id)) {
      released.push({ address: address.id, interface: iface.id, ...(address.dns_name ? { dns_name: address.dns_name } : {}) });
      const after: Address = structuredClone(address);
      after.interface = null;
      if (!keepDns) after.dns_name = null;
      after.meta.updated = ws.stamp();
      ws.finishUpdate("address", address, after);
    }
  }
  const after: Host = structuredClone(before);
  after.decommissioned = { at: ws.at, by: ws.principal, reason, kept_dns: keepDns, released };
  after.meta.updated = ws.stamp();
  ws.reservationChecks.delete(id);
  ws.finishUpdate("host", before, after);
  return ref("host", id);
}

export function reinstateHost(ws: Workspace, args: Json): ObjectRef {
  const b = new Body(args).only(["expected", "host"]);
  const id = b.reqUuid("host");
  const expected = b.expected();
  b.done();
  const before = ws.loadForChange("host", id, expected);
  ws.checkUnlocked(before);
  const decommission = before.decommissioned;
  if (!decommission) {
    throw new Problem("ipam.host.not_decommissioned", {
      status: 409,
      detail: `host ${before.name} is not decommissioned`,
      params: { host: before.name },
      errors: [fieldError("host", "ipam.host.not_decommissioned")],
    });
  }
  for (const release of decommission.released ?? []) {
    const address = ws.get("address", release.address);
    const iface = ws.get("interface", release.interface);
    const skip = (cause: "deleted" | "assigned" | "interface_gone") =>
      ws.warn(
        "ipam.host.reinstate_skipped",
        `${address?.ip ?? release.address} was not bound to ${before.name} again (${cause})`,
        ref("address", release.address),
        { address: release.address, ip: address?.ip ?? "", cause },
      );
    if (!address || address.meta.deleted) skip("deleted");
    else if (address.interface) skip("assigned");
    else if (!iface || iface.meta.deleted || iface.host !== id) skip("interface_gone");
    else {
      const after: Address = structuredClone(address);
      after.interface = release.interface;
      if (release.dns_name && !after.dns_name) after.dns_name = release.dns_name;
      after.meta.updated = ws.stamp();
      ws.finishUpdate("address", address, after);
    }
  }
  const after: Host = structuredClone(before);
  delete after.decommissioned;
  after.meta.updated = ws.stamp();
  ws.reservationChecks.add(id);
  ws.finishUpdate("host", before, after);
  return ref("host", id);
}
