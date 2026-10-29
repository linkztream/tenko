// The saved layout of every table (UI-Q4 of the UI plan): the columns a person hid, their
// order, their widths and the sort, one document per table, kept per user on the server under
// `table:<id>` (GET, PUT and DELETE /api/v1/auth/preferences, docs/access.md section 15).
// prefs.ts and widths.ts read and write through this store and keep their interfaces, so every
// table that uses DataGrid gets it for free.
//
// - The signed-in person's layouts are read from the API after sign-in. Until the answer is in,
//   and whenever the API cannot be reached, the copy in this browser applies
//   (`tenko-layout:<user>:<table>` in localStorage), so a table never waits for the server.
// - A change applies at once and is written after DEBOUNCE_MS without further change, with at
//   most one request in flight per table: a change made while one is in flight is sent when it
//   returns. A layout with nothing left in it is deleted rather than written.
// - The browser's values of the older per-browser stores (`tenko-grid:<table>` for order and
//   visibility, `tenko-grid-widths:<user>:<table>` for widths) are imported once per table when
//   the server has none for it, then forgotten.
// - A change that cannot be written (the API unreachable or failing) stays marked as pending in
//   the browser's copy; the store reads the server again later and then writes what is pending
//   (the person's latest change wins), and takes the server's value for everything else.
// - The documents are checked for their shape here (lists of strings, widths as numbers); the
//   table that applies one checks the column ids against its known columns and the widths
//   against its bounds (prefs.ts, widths.ts), so a crafted document cannot name a column that
//   does not exist or widen a table beyond its bounds.
import { createEffect, createRoot, createSignal, on, untrack, type Accessor, type Setter } from "solid-js";
import { api } from "../api/client";
import { isApiError } from "../api/problem";
import { session } from "../auth/session";

/** The version of the layout document this UI writes. */
export const LAYOUT_VERSION = 1;
/** Quiet time before a change is written, in milliseconds. */
export const DEBOUNCE_MS = 1000;
/** How long the store waits before it tries an unreachable API again, in milliseconds. */
export const RETRY_MS = 30_000;
/** The most columns a document names per list (the server's bound). */
export const MAX_COLUMNS = 128;

const CACHE = "tenko-layout:";
/** The order and visibility of the store before U6, per browser. */
export const LEGACY_COLUMNS = "tenko-grid:";
/** The widths of the store before U6, per browser and user. */
export const LEGACY_WIDTHS = "tenko-grid-widths:";

const TABLE_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const COLUMN_ID = /^[A-Za-z0-9._:-]{1,64}$/;

export interface LayoutSort {
  column: string;
  desc: boolean;
}

/** The layout of one table. An absent field means the table's default for it. */
export interface TableLayout {
  version: number;
  order?: string[];
  hidden?: string[];
  widths?: Record<string, number>;
  sort?: LayoutSort;
}

/** The fields a change sets; `undefined` returns a field to the table's default. */
export type LayoutPatch = { [K in Exclude<keyof TableLayout, "version">]?: TableLayout[K] | undefined };

export type SyncState = "idle" | "loading" | "ready" | "offline";

/** Whether `id` can be a key on the server (`table:<id>`); other tables stay in the browser. */
export function syncable(id: string): boolean {
  return TABLE_ID.test(id);
}

function strings(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: string[] = [];
  for (const x of v) if (typeof x === "string" && COLUMN_ID.test(x) && !out.includes(x)) out.push(x);
  return out.slice(0, MAX_COLUMNS);
}

/** A document read from the server or the browser, reduced to the fields of this version. */
export function sanitizeLayout(v: unknown): TableLayout | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const out: TableLayout = { version: LAYOUT_VERSION };
  const order = strings(o.order);
  if (order) out.order = order;
  const hidden = strings(o.hidden);
  if (hidden) out.hidden = hidden;
  if (o.widths && typeof o.widths === "object" && !Array.isArray(o.widths)) {
    const widths: Record<string, number> = {};
    for (const [id, w] of Object.entries(o.widths as Record<string, unknown>)) {
      if (COLUMN_ID.test(id) && typeof w === "number" && Number.isFinite(w) && w > 0) widths[id] = Math.round(w);
    }
    if (Object.keys(widths).length > 0) out.widths = widths;
  }
  const sort = o.sort as Record<string, unknown> | undefined;
  if (sort && typeof sort === "object" && typeof sort.column === "string" && COLUMN_ID.test(sort.column)) {
    out.sort = { column: sort.column, desc: sort.desc === true };
  }
  return isEmpty(out) ? null : out;
}

function isEmpty(layout: TableLayout): boolean {
  return !layout.order && !layout.hidden && !layout.widths && !layout.sort;
}

/** `layout` with `patch` applied; null when nothing is left. */
export function applyPatch(layout: TableLayout | null, patch: LayoutPatch): TableLayout | null {
  const next: TableLayout = { ...(layout ?? {}), version: LAYOUT_VERSION };
  for (const key of ["order", "hidden", "widths", "sort"] as const) {
    if (!(key in patch)) continue;
    const value = patch[key];
    if (value === undefined) delete next[key];
    else (next as unknown as Record<string, unknown>)[key] = value;
  }
  return sanitizeLayout(next);
}

// ---------------------------------------------------------------------------------------------
// The browser's copy

interface Cached {
  layout: TableLayout | null;
  /** The change is not on the server yet. */
  pending: boolean;
}

const cacheKey = (user: string, table: string) => `${CACHE}${user}:${table}`;

function readCache(user: string, table: string): Cached | null {
  try {
    const raw = localStorage.getItem(cacheKey(user, table));
    if (!raw) return null;
    const v = JSON.parse(raw) as { layout?: unknown; pending?: unknown };
    return { layout: sanitizeLayout(v.layout), pending: v.pending === true };
  } catch {
    return null;
  }
}

function writeCache(user: string, table: string, value: Cached): void {
  try {
    if (!value.pending && value.layout === null) localStorage.removeItem(cacheKey(user, table));
    else localStorage.setItem(cacheKey(user, table), JSON.stringify(value));
  } catch {
    // Storage unavailable: the layout lasts for this page (and on the server).
  }
}

function readJson(key: string): unknown {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as unknown) : undefined;
  } catch {
    return undefined;
  }
}

/** The values of the older per-browser stores for `table`, or null. */
export function readLegacy(user: string, table: string): TableLayout | null {
  const columns = readJson(LEGACY_COLUMNS + table) as { order?: unknown; hidden?: unknown } | undefined;
  const widths = readJson(`${LEGACY_WIDTHS}${user}:${table}`);
  return sanitizeLayout({ ...(columns && typeof columns === "object" ? columns : {}), widths });
}

function forgetLegacy(user: string, table: string): void {
  try {
    localStorage.removeItem(LEGACY_COLUMNS + table);
    localStorage.removeItem(`${LEGACY_WIDTHS}${user}:${table}`);
  } catch {
    // Nothing to forget.
  }
}

/** The tables the older stores and the browser's copy hold values for, for `user`. */
function browserTables(user: string): { legacy: Set<string>; cached: Set<string> } {
  const legacy = new Set<string>();
  const cached = new Set<string>();
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i) ?? "";
      if (key.startsWith(`${LEGACY_WIDTHS}${user}:`)) legacy.add(key.slice(`${LEGACY_WIDTHS}${user}:`.length));
      else if (key.startsWith(LEGACY_COLUMNS) && !key.startsWith(LEGACY_WIDTHS) && !key.startsWith("tenko-grid-groups:")) {
        legacy.add(key.slice(LEGACY_COLUMNS.length));
      } else if (key.startsWith(`${CACHE}${user}:`)) cached.add(key.slice(`${CACHE}${user}:`.length));
    }
  } catch {
    // Storage unavailable.
  }
  return { legacy, cached };
}

// ---------------------------------------------------------------------------------------------
// The store

interface Entry {
  user: string;
  table: string;
  get: Accessor<TableLayout | null>;
  set: Setter<TableLayout | null>;
  /** Counts the changes, so an answer knows whether it still describes the latest one. */
  seq: number;
  timer: ReturnType<typeof setTimeout> | undefined;
  inflight: boolean;
  /** A change waits for the request in flight. */
  queued: boolean;
}

const entries = new Map<string, Entry>();
const [syncState, setSyncState] = createSignal<SyncState>("idle");
let syncedUser: string | null = null;
let loadRun = 0;
let retryTimer: ReturnType<typeof setTimeout> | undefined;
let debounceMs = DEBOUNCE_MS;
let retryMs = RETRY_MS;

/** Where the server copy stands for the signed-in person. */
export { syncState };

function entry(user: string, table: string): Entry {
  const key = `${user}\u0000${table}`;
  let e = entries.get(key);
  if (!e) {
    const initial = readCache(user, table)?.layout ?? readLegacy(user, table);
    const [get, set] = createSignal<TableLayout | null>(initial, { equals: false });
    e = { user, table, get, set, seq: 0, timer: undefined, inflight: false, queued: false };
    entries.set(key, e);
  }
  return e;
}

const synced = (e: Entry) => syncedUser !== null && e.user === syncedUser && syncable(e.table);

/** The layout of `table` for `user`; null means the table's default. */
export function tableLayout(user: string | null | undefined, table: string): Accessor<TableLayout | null> {
  return entry(user ?? "-", table).get;
}

/** Changes the layout of `table` for `user`: at once here, on the server after DEBOUNCE_MS. */
export function patchLayout(user: string | null | undefined, table: string, patch: LayoutPatch): void {
  const e = entry(user ?? "-", table);
  const next = applyPatch(untrack(e.get), patch);
  e.set(next);
  e.seq++;
  writeCache(e.user, e.table, { layout: next, pending: synced(e) || syncedUser === null });
  if (!synced(e)) return;
  clearTimeout(e.timer);
  e.timer = setTimeout(() => void flush(e), debounceMs);
}

/** Returns `table` to its default for `user`: the key is deleted on the server at once. */
export function resetLayout(user: string | null | undefined, table: string): void {
  const e = entry(user ?? "-", table);
  e.set(null);
  e.seq++;
  writeCache(e.user, e.table, { layout: null, pending: synced(e) || syncedUser === null });
  if (!synced(e)) return;
  clearTimeout(e.timer);
  e.timer = undefined;
  void flush(e);
}

function transient(err: unknown): boolean {
  if (!isApiError(err)) return true;
  return err.status === 0 || err.status >= 500 || err.status === 429 || err.code === "auth.conflict";
}

async function flush(e: Entry): Promise<void> {
  e.timer = undefined;
  if (e.inflight) {
    e.queued = true;
    return;
  }
  if (!synced(e)) return;
  e.inflight = true;
  const seq = e.seq;
  const layout = untrack(e.get);
  try {
    if (layout) {
      await api.put("/api/v1/auth/preferences/{key}", {
        path: { key: `table:${e.table}` },
        body: { ...layout, version: LAYOUT_VERSION } as never,
      });
    } else {
      try {
        await api.delete("/api/v1/auth/preferences/{key}", { path: { key: `table:${e.table}` } });
      } catch (err) {
        if (!(isApiError(err) && err.status === 404)) throw err;
      }
    }
    if (seq === e.seq) writeCache(e.user, e.table, { layout, pending: false });
  } catch (err) {
    if (transient(err)) {
      // Pending in the browser's copy: written when the server is read again.
      setSyncState("offline");
      scheduleRetry();
    } else if (seq === e.seq) {
      // Refused for good (a bound of the server): the layout stays in this browser.
      writeCache(e.user, e.table, { layout, pending: false });
    }
  } finally {
    e.inflight = false;
    if (e.queued) {
      e.queued = false;
      if (!e.timer) void flush(e);
    }
  }
}

function scheduleRetry(): void {
  if (retryTimer !== undefined || syncedUser === null) return;
  retryTimer = setTimeout(() => {
    retryTimer = undefined;
    if (syncedUser !== null) void load(syncedUser);
  }, retryMs);
}

/** Reads the person's layouts from the server and reconciles them with the browser's copy. */
async function load(user: string): Promise<void> {
  const run = ++loadRun;
  setSyncState("loading");
  let items: { key: string; value: unknown }[];
  try {
    const page = await api.get("/api/v1/auth/preferences");
    items = page.items as { key: string; value: unknown }[];
  } catch {
    if (run !== loadRun || syncedUser !== user) return;
    setSyncState("offline");
    scheduleRetry();
    return;
  }
  if (run !== loadRun || syncedUser !== user) return;
  const server = new Map<string, TableLayout | null>();
  for (const item of items) {
    if (item.key.startsWith("table:")) server.set(item.key.slice("table:".length), sanitizeLayout(item.value));
  }
  const { legacy, cached } = browserTables(user);
  const tables = new Set([...server.keys(), ...legacy, ...cached]);
  for (const [, e] of entries) if (e.user === user) tables.add(e.table);
  for (const table of tables) {
    if (!syncable(table)) continue;
    const e = entry(user, table);
    const local = readCache(user, table);
    if (local?.pending) {
      // Changed here while the server was out of reach (or before it answered): this wins.
      e.set(local.layout);
      if (!e.inflight) void flush(e);
    } else if (server.has(table)) {
      const value = server.get(table) ?? null;
      e.set(value);
      writeCache(user, table, { layout: value, pending: false });
      if (legacy.has(table)) forgetLegacy(user, table);
    } else if (legacy.has(table)) {
      // Import the browser's old values once, then forget them.
      const value = readLegacy(user, table);
      forgetLegacy(user, table);
      e.set(value);
      e.seq++;
      writeCache(user, table, { layout: value, pending: value !== null });
      if (value) void flush(e);
    } else {
      // Gone from the server (reset in another browser): the default applies here too.
      e.set(null);
      writeCache(user, table, { layout: null, pending: false });
    }
  }
  setSyncState("ready");
}

function startSync(user: string | null): void {
  clearTimeout(retryTimer);
  retryTimer = undefined;
  syncedUser = user;
  loadRun++;
  if (user === null) {
    setSyncState("idle");
    return;
  }
  void load(user);
}

// A sign-in, a sign-out or another person starts over; a changed banner or language does not.
createRoot(() => {
  createEffect(
    on(
      () => session()?.user.id ?? null,
      (user) => {
        if (user !== syncedUser) startSync(user);
      },
    ),
  );
});

/** For tests: shorter waits than the product's. */
export function setLayoutTimingForTest(timing: { debounce?: number; retry?: number }): void {
  debounceMs = timing.debounce ?? DEBOUNCE_MS;
  retryMs = timing.retry ?? RETRY_MS;
}

/** For tests: forgets every layout and timer and stops syncing, as before a sign-in. */
export function resetLayoutStoreForTest(): void {
  debounceMs = DEBOUNCE_MS;
  retryMs = RETRY_MS;
  for (const e of entries.values()) clearTimeout(e.timer);
  entries.clear();
  startSync(null);
}

/** For tests: starts syncing for `user` as a sign-in does, and returns when the read is done. */
export function syncLayoutsForTest(user: string | null): Promise<void> {
  clearTimeout(retryTimer);
  retryTimer = undefined;
  syncedUser = user;
  loadRun++;
  return user === null ? Promise.resolve() : load(user);
}
