// Operations the UI calls before the OpenAPI document describes them: the routes of a Rust
// package that has not merged yet. `api.*` only accepts paths of the document, so these go
// through `pendingApi`, typed by the map `PendingOperations`.
//
// The map is extended per area by module augmentation from the area's own model module, so
// no area edits this file to add an operation:
//
//   declare module "../../api/pending" {
//     interface PendingOperations {
//       "get /api/v1/access/grants": { response: Page<GrantView> };
//       "post /api/v1/access/grants": { response: GrantView; body: GrantCreate };
//     }
//   }
//
// Keys are "<method> <path>" with the path as the document will spell it. The moment the
// document describes one of them, `StalePending` names the entry and the type check fails
// until the area deletes it and calls `api.*` instead, where the generated types take over.
// The mock side is `mock/pending-route.ts`.
import {
  rawRequest,
  type GetOptions,
  type Method,
  type PathParamNames,
  type PathsWith,
  type Query,
  type WriteOptions,
} from "./client";
import type { Page, Revision } from "./types";

/** One operation of the map: the success response and, for a write, the JSON body. */
export interface PendingOperation {
  response: unknown;
  body?: unknown;
}

/** Extended by the areas through module augmentation; see the head of this file. */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type -- filled by module augmentation
export interface PendingOperations {}

type PendingKey = keyof PendingOperations & string;

/** The pending paths that support `M`. */
export type PendingPaths<M extends Method> = {
  [K in PendingKey]: K extends `${M} ${infer P}` ? P : never;
}[PendingKey];

type Entry<M extends Method, P extends string> = `${M} ${P}` extends keyof PendingOperations
  ? PendingOperations[`${M} ${P}`]
  : never;

/** The response type of a pending operation. */
export type PendingResponse<M extends Method, P extends string> =
  Entry<M, P> extends { response: infer R } ? R : never;
/** The JSON body of a pending write; `never` for an operation without one. */
export type PendingBody<M extends Method, P extends string> = Entry<M, P> extends { body: infer B } ? B : never;

/**
 * Entries whose operation the document now describes. Must stay `never`: delete the named
 * entry from the area's model and call `api.*` instead.
 */
export type StalePending = {
  [K in PendingKey]: K extends `${infer M extends Method} ${infer P}` ? (P extends PathsWith<M> ? K : never) : K;
}[PendingKey];
const stalePending: [StalePending] extends [never] ? true : StalePending = true;
void stalePending;

/** Entries whose key is not "<method> /api/v1/...". Must stay `never`. */
export type MalformedPending = {
  [K in PendingKey]: K extends `${Method} /api/v1/${string}` ? never : K;
}[PendingKey];
const malformedPending: [MalformedPending] extends [never] ? true : MalformedPending = true;
void malformedPending;

type Optional<P extends string, T> = [PathParamNames<P>] extends [never] ? [options?: T] : [options: T];

function call<T>(method: Method, path: string, options: unknown): Promise<T> {
  return rawRequest<T>(method, path, (options ?? {}) as never);
}

/** The pending operations, one method per HTTP verb, with the conventions of `api.*`. */
export const pendingApi = {
  get<P extends PendingPaths<"get">>(
    path: P,
    ...[options]: Optional<P, GetOptions<P>>
  ): Promise<PendingResponse<"get", P>> {
    return call("get", path, options);
  },
  post<P extends PendingPaths<"post">>(
    path: P,
    ...[options]: Optional<P, WriteOptions<P, PendingBody<"post", P>>>
  ): Promise<PendingResponse<"post", P>> {
    return call("post", path, options);
  },
  put<P extends PendingPaths<"put">>(
    path: P,
    ...[options]: Optional<P, WriteOptions<P, PendingBody<"put", P>>>
  ): Promise<PendingResponse<"put", P>> {
    return call("put", path, options);
  },
  patch<P extends PendingPaths<"patch">>(
    path: P,
    ...[options]: Optional<P, WriteOptions<P, PendingBody<"patch", P>>>
  ): Promise<PendingResponse<"patch", P>> {
    return call("patch", path, options);
  },
  delete<P extends PendingPaths<"delete">>(
    path: P,
    ...[options]: Optional<P, WriteOptions<P, never>>
  ): Promise<PendingResponse<"delete", P>> {
    return call("delete", path, options);
  },
};

/** The paths of pending lists: GET operations that answer a `Page`. */
/**
 * Reads the answer of an operation the document describes as the working model an area built
 * before the route merged. A transitional cast: WP3.11c moves the last areas (the cluster
 * queue, the audit export page and the backup page) to the generated types and removes it.
 */
export function asWorkingModel<T>(answer: Promise<unknown>): Promise<T> {
  return answer as Promise<T>;
}

export type PendingListPaths = {
  [P in PendingPaths<"get">]: PendingResponse<"get", P> extends Page<unknown> ? P : never;
}[PendingPaths<"get">];

type ItemOf<P extends PendingListPaths> = PendingResponse<"get", P> extends Page<infer T> ? T : never;

export interface PendingListOptions {
  query?: Query | undefined;
  path?: Record<string, string | number> | undefined;
  signal?: AbortSignal | undefined;
  /** Stops after this many items (default 100,000). */
  max?: number | undefined;
}

/** Every page of a pending list, like `fetchAll` of `paginate.ts`. */
export async function pendingFetchAll<P extends PendingListPaths>(
  path: P,
  options: PendingListOptions = {},
): Promise<{ items: ItemOf<P>[]; revision: Revision; truncated: boolean }> {
  const max = options.max ?? 100_000;
  const items: ItemOf<P>[] = [];
  let revision: Revision | undefined;
  let cursor: string | null = null;
  for (;;) {
    const page: Page<ItemOf<P>> = await call("get", path, {
      query: { ...options.query, limit: 1000, cursor: cursor ?? undefined },
      path: options.path,
      signal: options.signal,
    });
    revision ??= page.revision;
    for (const item of page.items) {
      if (items.length >= max) return { items, revision, truncated: true };
      items.push(item);
    }
    if (!page.next_cursor) return { items, revision, truncated: false };
    cursor = page.next_cursor;
  }
}
