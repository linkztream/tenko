// Server-side rows for a grid: one list endpoint read page by page with its opaque cursor
// (`limit` and `cursor`, answered with `{ items, next_cursor, revision }`), filtered and
// sorted by the server through the query the view passes. The first page loads when the
// query changes; later pages load as the grid scrolls towards the end (`loadMore`).
//
// Live updates: the source subscribes to SSE topics. A relevant event newer than the rows
// reloads the pages already shown (so a scrolled list keeps its length) and marks the rows
// whose content changed, which the grid flashes once. A `reset` reloads from the start.
import { batch, createEffect, createSignal, on, onCleanup, type Accessor } from "solid-js";
import type { PathsWith, Query } from "../api/client";
import { events as defaultStream, type ApiEvent, type EventStream, type Topic } from "../api/events";
import { fetchPage, MAX_LIMIT } from "../api/paginate";

export interface ListSourceOptions<T> {
  path: PathsWith<"get">;
  /** Path parameters for nested lists such as /prefixes/{id}/addresses. */
  pathParams?: Accessor<Record<string, string | number> | undefined>;
  /** Filters and sort; a change reloads from the first page. */
  query: Accessor<Query>;
  rowId: (row: T) => string;
  /** Rows per page (default 200, at most 1,000). */
  pageSize?: number;
  /** While false, nothing loads (a view waiting for its scope). */
  enabled?: Accessor<boolean>;
  topics?: readonly Topic[];
  /** Only events this accepts reload the rows (default: every event of the topics). */
  relevant?: (event: ApiEvent) => boolean;
  /** How the change of a row is detected for the flash (default: JSON of the row). */
  signature?: (row: T) => string;
  stream?: EventStream;
  /** Pages reloaded at most on a live update (default 5); beyond that the list restarts. */
  maxLivePages?: number;
}

export interface ListSource<T> {
  rows: Accessor<readonly T[]>;
  /** A request is in flight (first page, next page or reload). */
  loading: Accessor<boolean>;
  /** The first page of the current query has not arrived yet. */
  initial: Accessor<boolean>;
  error: Accessor<unknown>;
  hasMore: Accessor<boolean>;
  loadMore: () => void;
  reload: () => void;
  /** The store revision the rows were read at. */
  revision: Accessor<number | undefined>;
  /** Rows whose content changed in the last live update. */
  flashed: (id: string) => boolean;
}

const FLASH_MS = 1400;

/** Must be called inside a component or another reactive owner. */
export function createListSource<T>(options: ListSourceOptions<T>): ListSource<T> {
  const stream = options.stream ?? defaultStream;
  const pageSize = Math.min(MAX_LIMIT, Math.max(1, options.pageSize ?? 200));
  const signature = options.signature ?? ((row: T) => JSON.stringify(row));

  const [rows, setRows] = createSignal<readonly T[]>([]);
  const [loading, setLoading] = createSignal(false);
  const [initial, setInitial] = createSignal(true);
  const [error, setError] = createSignal<unknown>(undefined);
  const [cursor, setCursor] = createSignal<string | null>(null);
  const [revision, setRevision] = createSignal<number | undefined>(undefined);
  const [flash, setFlash] = createSignal<ReadonlySet<string>>(new Set());

  let generation = 0;
  let controller: AbortController | undefined;
  let liveTimer: ReturnType<typeof setTimeout> | undefined;
  let flashTimer: ReturnType<typeof setTimeout> | undefined;

  const enabled = () => options.enabled?.() ?? true;
  const params = () => options.pathParams?.();

  const request = (cursorValue: string | null, signal: AbortSignal, atLeast?: number) =>
    fetchPage<T>(options.path, {
      limit: pageSize,
      cursor: cursorValue,
      query: options.query(),
      path: params(),
      atLeast,
      signal,
    });

  const begin = () => {
    controller?.abort();
    controller = new AbortController();
    generation += 1;
    return { gen: generation, signal: controller.signal };
  };

  const loadFirst = async () => {
    if (!enabled()) return;
    const { gen, signal } = begin();
    setLoading(true);
    setError(undefined);
    try {
      const page = await request(null, signal);
      if (gen !== generation) return;
      batch(() => {
        setRows(page.items);
        setCursor(page.next_cursor ?? null);
        setRevision(typeof page.revision === "number" ? page.revision : undefined);
        setInitial(false);
        setLoading(false);
      });
      if (typeof page.revision === "number") stream.resumeFrom(page.revision);
    } catch (err) {
      if (gen !== generation || (err instanceof DOMException && err.name === "AbortError")) return;
      batch(() => {
        setError(err);
        setInitial(false);
        setLoading(false);
      });
    }
  };

  const loadMore = async () => {
    const next = cursor();
    if (!next || loading() || !enabled()) return;
    const gen = generation;
    const signal = controller?.signal ?? new AbortController().signal;
    setLoading(true);
    try {
      const page = await request(next, signal);
      if (gen !== generation) return;
      batch(() => {
        const seen = new Set(rows().map(options.rowId));
        setRows([...rows(), ...page.items.filter((r) => !seen.has(options.rowId(r)))]);
        setCursor(page.next_cursor ?? null);
        setLoading(false);
      });
    } catch (err) {
      if (gen !== generation || (err instanceof DOMException && err.name === "AbortError")) return;
      batch(() => {
        setError(err);
        setLoading(false);
      });
    }
  };

  /** Reloads as many rows as are shown, at least as new as `atLeast`, and flashes changes. */
  const refresh = async (atLeast?: number) => {
    if (!enabled()) return;
    const shown = rows().length;
    const { gen, signal } = begin();
    setLoading(true);
    try {
      const items: T[] = [];
      let next: string | null = null;
      let pages = 0;
      let rev: number | undefined;
      do {
        const page = await request(next, signal, atLeast);
        if (gen !== generation) return;
        if (rev === undefined && typeof page.revision === "number") rev = page.revision;
        items.push(...page.items);
        next = page.next_cursor ?? null;
        pages += 1;
      } while (next && items.length < shown && pages < (options.maxLivePages ?? 5));
      const before = new Map(rows().map((r) => [options.rowId(r), signature(r)]));
      const changed = new Set<string>();
      for (const row of items) {
        const id = options.rowId(row);
        const old = before.get(id);
        if (old !== undefined && old !== signature(row)) changed.add(id);
      }
      batch(() => {
        setRows(items);
        setCursor(next);
        setRevision(rev);
        setLoading(false);
        setError(undefined);
        if (changed.size > 0) setFlash(changed);
      });
      if (changed.size > 0) {
        clearTimeout(flashTimer);
        flashTimer = setTimeout(() => setFlash(new Set<string>()), FLASH_MS);
      }
      if (rev !== undefined) stream.resumeFrom(rev);
    } catch (err) {
      if (gen !== generation || (err instanceof DOMException && err.name === "AbortError")) return;
      batch(() => {
        setError(err);
        setLoading(false);
      });
    }
  };

  // The query, the path parameters and the enabled flag decide what the list is.
  createEffect(
    on(
      () => [enabled(), JSON.stringify(params() ?? null), JSON.stringify(options.query())] as const,
      ([on]) => {
        if (!on) return;
        batch(() => {
          setInitial(true);
          setCursor(null);
        });
        void loadFirst();
      },
    ),
  );

  const offs = (options.topics ?? []).flatMap((topic) => [
    // eslint-disable-next-line solid/reactivity -- an event callback, like an event handler
    stream.subscribe(topic, (event) => {
      const rev = revision();
      if (event.revision !== undefined && rev !== undefined && event.revision <= rev) return;
      if (options.relevant && !options.relevant(event)) return;
      clearTimeout(liveTimer);
      liveTimer = setTimeout(() => void refresh(event.revision), 150);
    }),
    stream.onReset(topic, () => void loadFirst()),
  ]);

  onCleanup(() => {
    controller?.abort();
    clearTimeout(liveTimer);
    clearTimeout(flashTimer);
    for (const off of offs) off();
  });

  return {
    rows,
    loading,
    initial,
    error,
    hasMore: () => cursor() !== null,
    loadMore: () => void loadMore(),
    reload: () => void refresh(),
    revision,
    flashed: (id) => flash().has(id),
  };
}

/** Delays a true value by `ms` so a short request never flashes a loading state. */
export function delayed(value: Accessor<boolean>, ms = 300): Accessor<boolean> {
  const [late, setLate] = createSignal(false);
  let timer: ReturnType<typeof setTimeout> | undefined;
  createEffect(() => {
    clearTimeout(timer);
    if (value()) timer = setTimeout(() => setLate(true), ms);
    else setLate(false);
  });
  onCleanup(() => clearTimeout(timer));
  return late;
}
