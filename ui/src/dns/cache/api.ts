// The requests of the cache view (/dns/cache): the entries of a node's cache through the node
// command `dns.cache.list` (`GET /nodes/{id}/dns/cache`) in the canonical order of the names, read
// page by page following the cursor, and the flush of a suffix through `dns.cache.flush`. The
// entries are the names the clients asked, so every page read is audited by the server as
// `dns.cache.read`.
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";

export type DnsCacheEntry = components["schemas"]["DnsCacheEntry"];
type RecordData = components["schemas"]["RecordData"];
export type Rrsig = Extract<RecordData, { type: "RRSIG" }>;

/** Entries per page, the most the server lists at once. */
export const CACHE_PAGE = 1000;
/** Pages one read follows at most, so a read holds at most 10,000 entries. */
export const CACHE_PAGES = 10;

export interface CachePage {
  items: DnsCacheEntry[];
  next: string | null;
}

/** What one read gave: the entries in name order, and whether the cap cut it short. */
export interface CacheListing {
  suffix: string;
  items: DnsCacheEntry[];
  capped: boolean;
}

export async function listCache(id: number, suffix: string, cursor: string | undefined, signal?: AbortSignal): Promise<CachePage> {
  const query: { limit: number; suffix?: string; cursor?: string } = { limit: CACHE_PAGE };
  if (suffix) query.suffix = suffix;
  if (cursor) query.cursor = cursor;
  const page = await api.get("/api/v1/nodes/{id}/dns/cache", { path: { id }, query, signal });
  return { items: page.items, next: page.next_cursor ?? null };
}

/** Follows the cursor from the first page until the last, or until `pages` pages were read. */
export async function readPages(
  read: (cursor: string | undefined) => Promise<CachePage>,
  pages = CACHE_PAGES,
): Promise<{ items: DnsCacheEntry[]; capped: boolean }> {
  const items: DnsCacheEntry[] = [];
  let cursor: string | undefined;
  for (let n = 0; n < pages; n++) {
    const page = await read(cursor);
    items.push(...page.items);
    if (!page.next) return { items, capped: false };
    cursor = page.next;
  }
  return { items, capped: true };
}

/** Every entry at or below `suffix`, up to the cap. */
export async function readCache(id: number, suffix: string, signal?: AbortSignal): Promise<CacheListing> {
  const read = await readPages((cursor) => listCache(id, suffix, cursor, signal));
  return { suffix, ...read };
}

export async function flushCache(id: number, suffix: string): Promise<void> {
  await api.post("/api/v1/nodes/{id}/dns/cache/flush", { path: { id }, query: { suffix } });
}
