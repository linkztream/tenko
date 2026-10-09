// CSV export in the import vocabulary (crates/tenko-ipam/src/export/mod.rs): three files, one
// per entity, with the canonical target names as headers, so an export maps onto itself when
// it is imported again. UTF-8 with a byte order mark, comma separated, CRLF line ends (that
// is `toCsv`). Credentials are never exported; soft-deleted objects are left out.
import { compareCidr, compareIp, parseCidr, parseIp } from "../../ipam/ip";
import { toCsv } from "../../ipam/address/csv";
import { interfaceCell } from "../../hosts/csv";
import type { CustomValue, Interface, Meta } from "../types";
import { ipamState } from "./ipam/api";
import { liveOf } from "./ipam/state";

export type ExportKind = "prefixes" | "addresses" | "hosts";
export const EXPORT_KINDS: readonly ExportKind[] = ["prefixes", "addresses", "hosts"];

const COLUMNS: Readonly<Record<ExportKind, readonly string[]>> = {
  prefixes: ["prefix", "vrf", "role", "status", "vlan", "vlan_name", "site", "alarm_warn", "alarm_crit", "alloc", "description", "tags"],
  hosts: ["host", "tenant", "mode", "lock", "site", "description", "interfaces", "tags"],
  addresses: ["address", "vrf", "status", "dns_name", "host", "interface", "mac", "duid", "description", "tags"],
};

const OBJECT: Readonly<Record<ExportKind, "prefix" | "host" | "address">> = {
  prefixes: "prefix",
  hosts: "host",
  addresses: "address",
};

const ITEM_SEPARATOR = "; ";

function valueText(value: CustomValue | undefined): string {
  return value === undefined ? "" : String(value.value);
}

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** The file name of an export (`prefixes.csv`). */
export function exportFileName(kind: ExportKind): string {
  return `${kind}.csv`;
}

/** The CSV of one kind of object of the IPAM state. */
export function exportCsv(kind: ExportKind): string {
  const data = ipamState().data;
  const applies = OBJECT[kind];
  const customKeys = [...data.custom_field.values()]
    .filter((def) => def.applies_to.includes(applies))
    .map((def) => def.key)
    .sort();
  const header = [...COLUMNS[kind], ...customKeys.map((key) => `custom.${key}`)];
  const custom = (meta: Meta): string[] => customKeys.map((key) => valueText((meta.custom as Record<string, CustomValue>)[key]));
  const tags = (meta: Meta): string => (meta.tags ?? []).join(ITEM_SEPARATOR);

  const vrfs = new Map(liveOf(data, "vrf").map((v) => [v.id, v.name]));
  const tenants = new Map(liveOf(data, "tenant").map((t) => [t.id, t.name]));
  const sites = new Map(liveOf(data, "site").map((s) => [s.id, s.name]));
  const vlans = new Map(liveOf(data, "vlan").map((v) => [v.id, v]));
  const hosts = new Map(liveOf(data, "host").map((h) => [h.id, h]));
  const interfaces = new Map(liveOf(data, "interface").map((i) => [i.id, i]));

  const rows: string[][] = [];
  if (kind === "prefixes") {
    const sorted = liveOf(data, "prefix")
      .map((prefix) => ({ prefix, vrf: vrfs.get(prefix.vrf) ?? "", net: parseCidr(prefix.cidr) }))
      .sort((a, b) => compareText(a.vrf.toLowerCase(), b.vrf.toLowerCase()) || (a.net && b.net ? compareCidr(a.net, b.net) : 0));
    for (const { prefix, vrf } of sorted) {
      const vlan = prefix.vlan ? vlans.get(prefix.vlan) : undefined;
      rows.push([
        prefix.cidr,
        vrf,
        prefix.role,
        prefix.status,
        vlan ? String(vlan.vid) : "",
        vlan?.name ?? "",
        prefix.site ? (sites.get(prefix.site) ?? "") : "",
        prefix.alarm ? String(prefix.alarm.warn_pct) : "",
        prefix.alarm ? String(prefix.alarm.crit_pct) : "",
        prefix.alloc ?? "lowest",
        prefix.meta.description ?? "",
        tags(prefix.meta),
        ...custom(prefix.meta),
      ]);
    }
  } else if (kind === "hosts") {
    const byHost = new Map<string, Interface[]>();
    for (const iface of interfaces.values()) byHost.set(iface.host, [...(byHost.get(iface.host) ?? []), iface]);
    const sorted = [...hosts.values()]
      .map((host) => ({ host, tenant: tenants.get(host.tenant) ?? "" }))
      .sort((a, b) => compareText(a.tenant.toLowerCase(), b.tenant.toLowerCase()) || compareText(a.host.name, b.host.name));
    for (const { host, tenant } of sorted) {
      const own = [...(byHost.get(host.id) ?? [])].sort((a, b) => compareText(a.name, b.name));
      rows.push([
        host.name,
        tenant,
        host.mode,
        host.lock ? "true" : "false",
        host.site ? (sites.get(host.site) ?? "") : "",
        host.meta.description ?? "",
        own.map((i) => interfaceCell(i)).join(ITEM_SEPARATOR),
        tags(host.meta),
        ...custom(host.meta),
      ]);
    }
  } else {
    const sorted = liveOf(data, "address")
      .map((address) => ({ address, vrf: vrfs.get(address.vrf) ?? "", ip: parseIp(address.ip) }))
      .sort((a, b) => compareText(a.vrf.toLowerCase(), b.vrf.toLowerCase()) || (a.ip && b.ip ? compareIp(a.ip, b.ip) : 0));
    for (const { address, vrf } of sorted) {
      const iface = address.interface ? interfaces.get(address.interface) : undefined;
      const host = iface ? hosts.get(iface.host) : undefined;
      rows.push([
        address.ip,
        vrf,
        address.status,
        address.dns_name ?? "",
        host?.name ?? "",
        iface?.name ?? "",
        iface?.mac ?? "",
        iface?.duid ?? "",
        address.meta.description ?? "",
        tags(address.meta),
        ...custom(address.meta),
      ]);
    }
  }
  return toCsv(header, rows);
}
