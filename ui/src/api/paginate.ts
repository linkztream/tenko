// Lists of the API: `limit` (at most 1,000) and an opaque `cursor`, answered with
// `{ items, next_cursor, revision }`. The revision is where a view subscribes to events
// from (see events.ts), so every helper here returns it.
import { rawRequest, type PathsWith, type Query } from "./client";
import type { Page, Revision } from "./types";

export const MAX_LIMIT = 1000;

export interface PageOptions {
  limit?: number | undefined;
  cursor?: string | null | undefined;
  query?: Query | undefined;
  /** Path parameters, for nested lists such as /prefixes/{id}/addresses. */
  path?: Record<string, string | number> | undefined;
  /** Read your own write: the server answers from at least this revision. */
  atLeast?: Revision | undefined;
  signal?: AbortSignal | undefined;
}

function pageQuery(o: PageOptions): Query {
  return {
    ...o.query,
    limit: o.limit === undefined ? undefined : Math.min(Math.max(1, Math.floor(o.limit)), MAX_LIMIT),
    cursor: o.cursor ?? undefined,
    at_least: o.atLeast,
  };
}

/** One page of a list. */
export function fetchPage<T>(path: PathsWith<"get">, options: PageOptions = {}): Promise<Page<T>> {
  return rawRequest<Page<T>>("get", path, { query: pageQuery(options), path: options.path, signal: options.signal });
}

/** Every page of a list in order, following `next_cursor` until it is absent. */
export async function* pages<T>(path: PathsWith<"get">, options: PageOptions = {}): AsyncGenerator<Page<T>> {
  let cursor = options.cursor ?? null;
  for (;;) {
    const page = await fetchPage<T>(path, { ...options, cursor });
    yield page;
    if (!page.next_cursor) return;
    cursor = page.next_cursor;
  }
}

export interface AllItems<T> {
  items: T[];
  /** The revision of the first page: events after it cover every later change. */
  revision: Revision;
  /** True when `max` stopped the walk before the end of the list. */
  truncated: boolean;
}

/** Collects a whole list, up to `max` items (default 100,000). */
export async function fetchAll<T>(
  path: PathsWith<"get">,
  options: PageOptions & { max?: number } = {},
): Promise<AllItems<T>> {
  const max = options.max ?? 100_000;
  const items: T[] = [];
  let revision: Revision | undefined;
  for await (const page of pages<T>(path, { limit: MAX_LIMIT, ...options })) {
    revision ??= page.revision;
    for (const item of page.items) {
      if (items.length >= max) return { items, revision, truncated: true };
      items.push(item);
    }
  }
  return { items, revision: revision ?? 0, truncated: false };
}
