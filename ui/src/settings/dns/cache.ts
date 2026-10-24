// What the node's DNS cache holds (the cache section of /settings/dns): the entries through the
// node command `dns.cache.list` (`GET /nodes/{id}/dns/cache`) in the canonical order of the
// names, read page by page following the cursor, the tree of names they are shown in, and the
// flush of a suffix through the node command `dns.cache.flush`. The entries are the names the
// clients asked, so every page read is audited by the server as `dns.cache.read`; the section
// reads only when asked to.
import { api } from "../../api/client";
import type { components } from "../../api/generated/schema";
import { canonical, recordText, validName } from "../../dns/model";
import { rcodeName } from "../../dns/log/model";

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

/** The suffix as the filter sends it, or null when it is not a name; "" is no filter. */
export function cacheSuffix(typed: string): string | null {
  const name = canonical(typed);
  if (name === "") return "";
  return validName(name) ? name : null;
}

/** The data column of an entry: its records in zone file form, a record of another type than
 * the question (the CNAME of a chain) with its type; NXDOMAIN or NODATA for a negative answer.
 * The signatures are rows of their own (see `signatures`). */
export function entryData(entry: DnsCacheEntry): string {
  const records = entry.records.filter((record) => record.type !== "RRSIG");
  if (records.length === 0) return entry.rcode === 0 ? "NODATA" : rcodeName(entry.rcode);
  return records
    .map((record) => {
      const text = recordText(record);
      return record.type === entry.type ? text : `${record.type} ${text}`;
    })
    .join(", ");
}

/** The RRSIG records of an entry's answer, in the order received. */
export function signatures(entry: DnsCacheEntry): Rrsig[] {
  return entry.records.filter((record): record is Rrsig => record.type === "RRSIG");
}

/** An RRSIG time (seconds since 1970 modulo 2^32, RFC 4034 section 3.1.5) as the instant
 * nearest to `now` that it can stand for. */
export function rrsigTime(value: number, now = Date.now()): Date {
  const span = 2 ** 32;
  const seconds = Math.floor(now / 1000);
  return new Date((value + Math.round((seconds - value) / span) * span) * 1000);
}

/** A time to the minute in UTC, as the Windows DNS manager shows signature times: `2026-11-12 02:08`. */
export function utcMinute(time: Date): string {
  return time.toISOString().slice(0, 16).replace("T", " ");
}

/** Seconds left as the table shows them: `45 s`, `12 min`, `3 h`. */
export function ttlLeft(seconds: number): { value: number; unit: "s" | "min" | "h" } {
  if (seconds < 120) return { value: seconds, unit: "s" };
  if (seconds < 7_200) return { value: Math.floor(seconds / 60), unit: "min" };
  return { value: Math.floor(seconds / 3_600), unit: "h" };
}

// The tree of names, as the cache view of the Windows DNS manager shows it: one node per label
// from the root down, each holding the entries whose name is exactly that node.

export interface CacheNode {
  /** A number unique in the tree, for element ids. */
  id: number;
  /** The full name in canonical form; `.` for the root. */
  name: string;
  /** The label relative to the parent; "" for the root. */
  label: string;
  /** 0 for the root. */
  depth: number;
  /** The parent's name; null for the root. */
  parent: string | null;
  entries: DnsCacheEntry[];
  /** In canonical order. */
  children: CacheNode[];
}

export interface CacheTree {
  root: CacheNode;
  byName: ReadonlyMap<string, CacheNode>;
  /** The suffix the entries were read with; "" for none. */
  suffix: string;
}

/** The labels of a name from the root inwards: `www.example.test` is `test`, `example`, `www`.
 * An escaped dot (`\.`) stays inside its label. */
export function nameLabels(name: string): string[] {
  if (name === "." || name === "") return [];
  const labels: string[] = [];
  let label = "";
  for (let i = 0; i < name.length; i++) {
    const c = name[i];
    if (c === "\\" && i + 1 < name.length) {
      label += c + name[i + 1];
      i++;
    } else if (c === ".") {
      labels.push(label);
      label = "";
    } else {
      label += c;
    }
  }
  labels.push(label);
  return labels.filter((l) => l !== "").reverse();
}

/** The names from the root to `name`, both included: `.`, `test`, `example.test`. */
export function pathTo(name: string): string[] {
  const out = ["."];
  let current = "";
  for (const label of nameLabels(name)) {
    current = current ? `${label}.${current}` : label;
    out.push(current);
  }
  return out;
}

/** Rows the right pane, and the folders under each folder of the tree, show at first; each
 * "show more" adds as many again. A folder with 100,000 names under it never puts 100,000
 * elements in the page. */
export const WINDOW = 200;

/** An empty tree for entries read with `suffix`, to which `add` adds them. Adding is O(1) for
 * an entry whose name is in the tree and O(labels) for a new name, so the whole build is
 * linear in the entries; the pages of one read are added in turn, and the names under a
 * folder could be added when that folder is read on its own. Entries come in canonical name
 * order, so every node's children are in that order too. The path to the suffix is always
 * in the tree. */
export function createCacheTree(suffix = ""): CacheTree & { add(entries: readonly DnsCacheEntry[]): void } {
  let next = 0;
  const root: CacheNode = { id: next++, name: ".", label: "", depth: 0, parent: null, entries: [], children: [] };
  const byName = new Map<string, CacheNode>([[".", root]]);
  const index = new Map<CacheNode, Map<string, CacheNode>>();
  const ensure = (name: string): CacheNode => {
    const known = byName.get(name);
    if (known) return known;
    let node = root;
    for (const label of nameLabels(name)) {
      let labels = index.get(node);
      if (!labels) {
        labels = new Map();
        index.set(node, labels);
      }
      let child = labels.get(label);
      if (!child) {
        const full = node === root ? label : `${label}.${node.name}`;
        child = { id: next++, name: full, label, depth: node.depth + 1, parent: node.name, entries: [], children: [] };
        labels.set(label, child);
        node.children.push(child);
        byName.set(full, child);
      }
      node = child;
    }
    return node;
  };
  if (suffix && suffix !== ".") ensure(suffix);
  return {
    root,
    byName,
    suffix: suffix === "." ? "" : suffix,
    add(entries) {
      for (const entry of entries) ensure(entry.name || ".").entries.push(entry);
    },
  };
}

/** The tree of the entries of one read. */
export function buildCacheTree(entries: readonly DnsCacheEntry[], suffix = ""): CacheTree {
  const tree = createCacheTree(suffix);
  tree.add(entries);
  return tree;
}

/** Whether a node is a folder of the tree: the root, a name with names under it, and the
 * suffix read. Any other name is a row of its parent's folder only. */
export function isFolder(tree: CacheTree, node: CacheNode): boolean {
  return node === tree.root || node.children.length > 0 || node.name === tree.suffix;
}

export function folderChildren(tree: CacheTree, node: CacheNode): CacheNode[] {
  return node.children.filter((child) => isFolder(tree, child));
}

/** An item of the tree pane: a folder, or the "show more" of the folders under one. */
export type TreeItem = { kind: "folder"; node: CacheNode } | { kind: "more"; parent: CacheNode; hidden: number };

/** The items shown, in pre-order: the root, and under each expanded folder the first of its
 * folders (`shown` of them, `window` unless said otherwise) with a "show more" after them. */
export function visibleFolders(
  tree: CacheTree,
  expanded: ReadonlySet<string>,
  shown: ReadonlyMap<string, number> = new Map(),
  window = WINDOW,
): TreeItem[] {
  const out: TreeItem[] = [];
  const walk = (node: CacheNode) => {
    out.push({ kind: "folder", node });
    if (!expanded.has(node.name)) return;
    const folders = folderChildren(tree, node);
    const limit = shown.get(node.name) ?? window;
    for (const child of folders.slice(0, limit)) walk(child);
    if (folders.length > limit) out.push({ kind: "more", parent: node, hidden: folders.length - limit });
  };
  walk(tree.root);
  return out;
}

/** A row of the right pane: a folder under the one selected, an entry, or a signature of one.
 * `label` is the name relative to the folder selected, null for the folder's own records. */
export type PaneRow =
  | { kind: "folder"; node: CacheNode }
  | { kind: "entry"; entry: DnsCacheEntry; label: string | null }
  | { kind: "signature"; entry: DnsCacheEntry; record: Rrsig; label: string | null };

/** The rows of a folder, as the Windows DNS manager lists them: the folders under it first,
 * then its own records, then the records of the names under it that are no folders; each
 * entry is followed by its signatures. The pane shows a window of them. */
export function paneRows(tree: CacheTree, node: CacheNode): PaneRow[] {
  const rows: PaneRow[] = [];
  const records = (entries: readonly DnsCacheEntry[], label: string | null) => {
    for (const entry of entries) {
      rows.push({ kind: "entry", entry, label });
      for (const record of signatures(entry)) rows.push({ kind: "signature", entry, record, label });
    }
  };
  for (const child of node.children) if (isFolder(tree, child)) rows.push({ kind: "folder", node: child });
  records(node.entries, null);
  for (const child of node.children) if (!isFolder(tree, child)) records(child.entries, child.label);
  return rows;
}
