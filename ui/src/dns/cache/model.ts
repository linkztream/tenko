// The pure parts of the cache view (/dns/cache): the suffix filter, the data column of an entry,
// its signatures, the time left, and the tree of names the entries are shown in with its folders
// and the rows of the right pane.
import { canonical, recordText, validName } from "../model";
import { rcodeName } from "../log/model";
import type { DnsCacheEntry, Rrsig, SvcRecord } from "./api";

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
      const text = isSvc(record) ? svcbText(record) : recordText(record);
      return record.type === entry.type ? text : `${record.type} ${text}`;
    })
    .join(records.some(isSvc) ? "; " : ", ");
}

// SVCB and HTTPS records (RFC 9460). The API carries a parameter as its key and its value in wire
// form (hex); the presentation format of section 2.1 is `priority target key=value ...` in key
// order, the registered keys by name (section 14.3.2) and any other as `keyNNNNN`.

/** The registered keys of RFC 9460 by number. */
const SVC_KEYS: Readonly<Record<number, string>> = {
  0: "mandatory",
  1: "alpn",
  2: "no-default-alpn",
  3: "port",
  4: "ipv4hint",
  5: "ech",
  6: "ipv6hint",
};

function keyName(key: number): string {
  return SVC_KEYS[key] ?? `key${key}`;
}

/** The bytes of a hex string, or null when it is not one. */
function hexBytes(hex: string): number[] | null {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return null;
  const out: number[] = [];
  for (let i = 0; i < hex.length; i += 2) out.push(Number.parseInt(hex.slice(i, i + 2), 16));
  return out;
}

const BACKSLASH = "\\";

/** A byte string as a zone file character-string without quotes (RFC 1035 section 5.1): the
 * printable ASCII characters as they are, a backslash and a double quote with a backslash in
 * front, every other byte (the space too) as a backslash and three decimal digits. In an alpn
 * list (`list`) a comma and a backslash of an identifier are escaped for the list first and then
 * for the zone file, RFC 9460 appendix D: `\\,` and `\\\\`. */
function escapeBytes(bytes: readonly number[], list = false): string {
  let out = "";
  for (const byte of bytes) {
    const c = String.fromCharCode(byte);
    if (byte < 0x21 || byte > 0x7e) out += `${BACKSLASH}${String(byte).padStart(3, "0")}`;
    else if (list && (c === "," || c === BACKSLASH)) out += c === "," ? `${BACKSLASH}${BACKSLASH},` : BACKSLASH.repeat(4);
    else if (c === BACKSLASH || c === '"') out += `${BACKSLASH}${c}`;
    else out += c;
  }
  return out;
}

/** Sixteen bytes as an IPv6 address in the compressed form of RFC 5952 (the longest run of two or
 * more zero groups as `::`, the first on a tie). */
function ipv6(bytes: readonly number[]): string {
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(((bytes[i] ?? 0) << 8) | (bytes[i + 1] ?? 0));
  let start = -1;
  let length = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let end = i;
    while (end < 8 && groups[end] === 0) end++;
    if (end - i > length) {
      start = i;
      length = end - i;
    }
    i = end;
  }
  const hex = (list: number[]) => list.map((g) => g.toString(16)).join(":");
  if (length < 2) return hex(groups);
  return `${hex(groups.slice(0, start))}::${hex(groups.slice(start + length))}`;
}

/** The value of a registered key in presentation form ("" for a key that takes none), or null
 * when the wire form does not fit the key (a port of three bytes): the parameter is then
 * written in the generic form. */
function knownValue(key: number, bytes: readonly number[]): string | null {
  const u16 = (i: number) => ((bytes[i] ?? 0) << 8) | (bytes[i + 1] ?? 0);
  const chunks = (size: number) => Array.from({ length: bytes.length / size }, (_, n) => bytes.slice(n * size, (n + 1) * size));
  switch (key) {
    case 0:
      if (bytes.length === 0 || bytes.length % 2 !== 0) return null;
      return chunks(2)
        .map((_, n) => keyName(u16(n * 2)))
        .join(",");
    case 1: {
      // Length-prefixed identifiers, RFC 9460 section 7.1.
      const ids: string[] = [];
      for (let i = 0; i < bytes.length; ) {
        const end = i + 1 + (bytes[i] ?? 0);
        if (end > bytes.length || end === i + 1) return null;
        ids.push(escapeBytes(bytes.slice(i + 1, end), true));
        i = end;
      }
      return ids.length > 0 ? ids.join(",") : null;
    }
    case 2:
      return bytes.length === 0 ? "" : null;
    case 3:
      return bytes.length === 2 ? String(u16(0)) : null;
    case 4:
      return bytes.length > 0 && bytes.length % 4 === 0 ? chunks(4).map((a) => a.join(".")).join(",") : null;
    case 5:
      return bytes.length > 0 ? btoa(String.fromCharCode(...bytes)) : null;
    case 6:
      return bytes.length > 0 && bytes.length % 16 === 0 ? chunks(16).map(ipv6).join(",") : null;
    default:
      return null;
  }
}

/** One parameter as `key=value`, or the bare key when it has no value. */
function svcParamText(param: { key: number; value: string }): string {
  const bytes = hexBytes(param.value);
  // A value that is no hex cannot be decoded: shown as it came, never guessed at.
  if (bytes === null) return `${keyName(param.key)}=${param.value}`;
  const known = knownValue(param.key, bytes);
  if (known !== null) return known === "" ? keyName(param.key) : `${keyName(param.key)}=${known}`;
  // The generic form, `key65280=\000\001`; also for a registered key whose value does not fit.
  return bytes.length === 0 ? `key${param.key}` : `key${param.key}=${escapeBytes(bytes)}`;
}

/** An SVCB or HTTPS record in the presentation format of RFC 9460 section 2.1: the priority, the
 * target and the parameters in key order, `1 . alpn=h2,h3 ipv4hint=192.0.2.10`. An alias record
 * (priority 0) is the priority and the target. */
export function svcbText(record: SvcRecord): string {
  const params = [...record.params].sort((a, b) => a.key - b.key).map(svcParamText);
  return [String(record.priority), record.target, ...params].join(" ");
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
