// CSV of selected hosts in the import vocabulary, the format of `GET /exports/hosts.csv`
// (crates/tenko-ipam/src/export): `host, tenant, mode, lock, site, description, interfaces,
// tags`; interfaces as `name`, `name=mac`, `name=mac=duid` or `name==duid`, joined with "; ".
import { fetchAll } from "../api/paginate";
import type { Host, Interface } from "../api/types";
import { toCsv } from "../ipam/address/csv";

export const HOST_COLUMNS = ["host", "tenant", "mode", "lock", "site", "description", "interfaces", "tags"] as const;

/** One interface in the export vocabulary. */
export function interfaceCell(i: Pick<Interface, "name" | "mac" | "duid">): string {
  if (i.mac && i.duid) return `${i.name}=${i.mac}=${i.duid}`;
  if (i.mac) return `${i.name}=${i.mac}`;
  if (i.duid) return `${i.name}==${i.duid}`;
  return i.name;
}

export async function hostsCsv(
  hosts: readonly Host[],
  tenantName: (id: string) => string,
  siteName: (id: string) => string,
): Promise<string> {
  const rows = await Promise.all(
    hosts.map(async (h) => {
      const ifaces = await fetchAll<Interface>("/api/v1/hosts/{id}/interfaces", { path: { id: h.id } }).catch(() => ({
        items: [] as Interface[],
      }));
      const live = ifaces.items.filter((i) => !i.meta.deleted).sort((a, b) => a.name.localeCompare(b.name));
      return [
        h.name,
        tenantName(h.tenant),
        h.mode,
        h.lock ? "true" : "false",
        h.site ? siteName(h.site) : "",
        h.meta.description ?? "",
        live.map(interfaceCell).join("; "),
        (h.meta.tags ?? []).join("; "),
      ];
    }),
  );
  return toCsv(HOST_COLUMNS, rows);
}
