// What the node's infrastructure cache holds (the infrastructure section of /settings/dns,
// WP10.4): a page of zone cuts through the node command `dns.infra.list`
// (`GET /nodes/{id}/dns/infra`) in the canonical order of the names, the cursor of the next
// page, and the flush through the node command `dns.infra.flush`, of the cuts at or below a
// suffix or of all of them. The cache holds the authority servers of zones and no client data,
// so a read is recorded but not audited; the flush is audited (`dns.infra.flush`).
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";

export type InfraCut = components["schemas"]["InfraCutItem"];
export type InfraServer = components["schemas"]["InfraServerItem"];
export type InfraAddress = components["schemas"]["InfraAddressItem"];

/** Zone cuts per page. */
export const INFRA_PAGE = 50;

export interface InfraPage {
  items: InfraCut[];
  next: string | null;
}

export async function listInfra(id: number, suffix: string, cursor: string | undefined, signal?: AbortSignal): Promise<InfraPage> {
  const query: { limit: number; suffix?: string; cursor?: string } = { limit: INFRA_PAGE };
  if (suffix) query.suffix = suffix;
  if (cursor) query.cursor = cursor;
  const page = await api.get("/api/v1/nodes/{id}/dns/infra", { path: { id }, query, signal });
  return { items: page.items, next: page.next_cursor ?? null };
}

/** Flushes the cuts at or below `suffix`, or everything for ""; the number of entries dropped. */
export async function flushInfra(id: number, suffix: string): Promise<number> {
  const answer = await api.post("/api/v1/nodes/{id}/dns/infra/flush", { path: { id }, query: suffix ? { suffix } : {} });
  return answer.entries;
}

/** The capabilities of an address the table names: what it lacks or what is wrong with it. */
export type Capability = "edns" | "no_edns" | "tcp_only" | "lower_case" | "lame" | "down";

export function capabilities(address: InfraAddress): Capability[] {
  const out: Capability[] = [];
  if (address.edns === true) out.push("edns");
  if (address.edns === false) out.push("no_edns");
  if (address.tcp_only) out.push("tcp_only");
  if (address.lower_case) out.push("lower_case");
  if (address.lame) out.push("lame");
  if (address.down) out.push("down");
  return out;
}

/** The addresses of a cut, each with the name of its server, in the order the cut lists them. */
export function addressesOf(cut: InfraCut): { server: string; address: InfraAddress }[] {
  return cut.servers.flatMap((server) => (server.addresses.length > 0 ? server.addresses.map((address) => ({ server: server.name, address })) : []));
}
