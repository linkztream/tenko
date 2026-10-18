// What the node's DNS cache holds (the cache section of /settings/dns): a page of the entries
// through the node command `dns.cache.list` (`GET /nodes/{id}/dns/cache`) in the canonical
// order of the names, the cursor of the next page, and the flush of a suffix through the node
// command `dns.cache.flush`. The entries are the names the clients asked, so every page read is
// audited by the server as `dns.cache.read`; the section reads only when asked to.
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";
import { canonical, recordText, validName } from "../../dns/model";
import { rcodeName } from "../../dns/log/model";

export type DnsCacheEntry = components["schemas"]["DnsCacheEntry"];

/** Entries per page. */
export const CACHE_PAGE = 100;

export interface CachePage {
  items: DnsCacheEntry[];
  next: string | null;
}

export async function listCache(id: number, suffix: string, cursor: string | undefined, signal?: AbortSignal): Promise<CachePage> {
  const query: { limit: number; suffix?: string; cursor?: string } = { limit: CACHE_PAGE };
  if (suffix) query.suffix = suffix;
  if (cursor) query.cursor = cursor;
  const page = await api.get("/api/v1/nodes/{id}/dns/cache", { path: { id }, query, signal });
  return { items: page.items, next: page.next_cursor ?? null };
}

export async function flushCache(id: number, suffix: string): Promise<void> {
  await api.post("/api/v1/nodes/{id}/dns/cache/flush", { path: { id }, query: { suffix } });
}

/** The suffix as the filter sends it, or null when it is not a name; "" is no filter. */
export function cacheSuffix(typed: string): string | null {
  const name = canonical(typed);
  if (name === "") return "";
  return validName(name) ? name : null;
}

/** The data column of an entry: its records in zone file form, a record of another type than
 * the question (the CNAME of a chain) with its type; NXDOMAIN or NODATA for a negative answer. */
export function entryData(entry: DnsCacheEntry): string {
  if (entry.records.length === 0) return entry.rcode === 0 ? "NODATA" : rcodeName(entry.rcode);
  return entry.records
    .map((record) => {
      const text = recordText(record);
      return record.type === entry.type ? text : `${record.type} ${text}`;
    })
    .join(", ");
}

/** Seconds left as the table shows them: `45 s`, `12 min`, `3 h`. */
export function ttlLeft(seconds: number): { value: number; unit: "s" | "min" | "h" } {
  if (seconds < 120) return { value: seconds, unit: "s" };
  if (seconds < 7_200) return { value: Math.floor(seconds / 60), unit: "min" };
  return { value: Math.floor(seconds / 3_600), unit: "h" };
}
