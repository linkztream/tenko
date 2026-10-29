// The pure parts of the cache view (/dns/cache): the suffix filter, the data column of an entry,
// its signatures, the time left, and the tree of names the entries are shown in with its folders
// and the rows of the right pane.
import { canonical, recordText, validName } from "../model";
import { rcodeName } from "../log/model";
import { svcbText } from "../svcb";
import type { DnsCacheEntry, Rrsig, SvcRecord } from "./api";

// The formatter lives with the zone pages' model (shared); the cache view keeps exporting it.
export { svcbText };

/** The suffix as the filter sends it, or null when it is not a name; "" is no filter. */
export function cacheSuffix(typed: string): string | null {
  const name = canonical(typed);
  if (name === "") return "";
  return validName(name) ? name : null;
}

function isSvc(record: { type: string }): record is SvcRecord {
  return record.type === "SVCB" || record.type === "HTTPS";
}

/** The data column of an entry: its records in zone file form (an HTTPS or SVCB record as its
 * SvcParams, see `svcbText`), a record of another type than the question (the CNAME of a
 * chain) with its type; NXDOMAIN or NODATA for a negative answer. The signatures are rows of
 * their own (see `signatures`). Records are joined by ", ", SVCB and HTTPS records by "; "
 * since their values hold commas. */
export function entryData(entry: DnsCacheEntry): string {
  const records = entry.records.filter((record) => record.type !== "RRSIG");
  if (records.length === 0) return entry.rcode === 0 ? "NODATA" : rcodeName(entry.rcode);
  return records
    .map((record) => {
      const text = recordText(record);
      return record.type === entry.type ? text : `${record.type} ${text}`;
    })
    .join(records.some(isSvc) ? "; " : ", ");
}

/** The value all of `values` share, or null when they differ or there are fewer than `least` of
 * them (one row has no majority to say once). The rule behind "State · all insecure" in a column
 * header, written with no knowledge of the cache so the grid can take it over. */
export function uniform<T>(values: readonly T[], least = 2): T | null {
  const [first] = values;
  if (values.length < least || first === undefined) return null;
  return values.every((value) => value === first) ? first : null;
}

/** The validation state every entry row of `rows` has, when they all have the same one. */
export function sharedState(rows: readonly PaneRow[]): DnsCacheEntry["state"] | null {
  return uniform(rows.flatMap((row) => (row.kind === "entry" ? [row.entry.state] : [])));
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
