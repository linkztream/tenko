// A thin, typed client of the public API (API-02): the only module that calls fetch for
// /api. Paths are the keys of the generated OpenAPI types, so a path that is not in the
// document does not compile. Conventions (docs/plans/phase-1-execution.md, section 4):
//
// - POST carries an `Idempotency-Key` (API-04). Pass the same `idempotencyKey` when
//   retrying one logical operation; otherwise every call gets a fresh one. `null` sends
//   none: the server buffers keyed requests under a smaller size limit than an upload.
// - Every write (POST, PUT, PATCH, DELETE) carries `If-Match: "<revision>"` when `ifMatch` is
//   given; use the revision from the object you edit, or ANY_REVISION where no revision
//   applies. A POST that acts on an existing object (an activation, say) passes it too.
// - A body is JSON unless it is a FormData (multipart, the browser sets the boundary) or a
//   Blob, which includes File: a Blob is sent as it is with its own type as `Content-Type`
//   (`application/octet-stream` when it has none) and is never JSON-encoded.
// - Errors are thrown as ApiError with the problem's stable code (see problem.ts).
//
// Request and response types come from the OpenAPI document. While an operation is still
// a stub without schemas, provisional.ts supplies them; once the document describes the
// operation, the generated type wins.
import type { paths } from "./generated/schema";
import { ApiError, CLIENT_CODES, toProblem } from "./problem";
import type { ProvisionalBodies, ProvisionalResponses } from "./provisional";

export type Method = "get" | "post" | "put" | "patch" | "delete";
export type ApiPath = keyof paths & string;
export type Revision = number | string;

/** `If-Match: *`: the change applies whatever the current revision is. */
export const ANY_REVISION = "*";

/** Paths that support a method. */
export type PathsWith<M extends Method> = {
  [P in ApiPath]: paths[P] extends { [K in M]: infer O } ? ([O] extends [never | undefined] ? never : P) : never;
}[ApiPath];

type Operation<P extends ApiPath, M extends Method> = paths[P] extends { [K in M]: infer O } ? O : never;

type SuccessStatus = 200 | 201 | 202 | 204;
type JsonOf<R> = R extends { content: { "application/json": infer T } } ? T : never;
type SpecResponse<O> = O extends { responses: infer R }
  ? { [S in keyof R]: S extends SuccessStatus ? (S extends 204 ? undefined : JsonOf<R[S]>) : never }[keyof R]
  : never;
type SpecBody<O> = O extends { requestBody?: infer RB } ? JsonOf<NonNullable<RB>> : never;

/** The spec's type when the document has one, else the provisional one, else unknown. */
type Resolve<Spec, Provisional> = [Spec] extends [never] ? ([Provisional] extends [never] ? unknown : Provisional) : Spec;

type Key<M extends Method, P extends string> = `${M} ${P}`;
type ProvisionalResponse<M extends Method, P extends string> =
  Key<M, P> extends keyof ProvisionalResponses ? ProvisionalResponses[Key<M, P>] : never;
type ProvisionalBody<M extends Method, P extends string> =
  Key<M, P> extends keyof ProvisionalBodies ? ProvisionalBodies[Key<M, P>] : never;

/** The response type of an operation. */
export type ResponseOf<M extends Method, P extends ApiPath> = Resolve<
  SpecResponse<Operation<P, M>>,
  ProvisionalResponse<M, P>
>;
/** The JSON request body of an operation. */
export type BodyOf<M extends Method, P extends ApiPath> = Resolve<SpecBody<Operation<P, M>>, ProvisionalBody<M, P>>;

/**
 * Provisional entries whose operation the document now describes. Must stay `never`:
 * when the backend adds a schema, delete the named entry from provisional.ts.
 */
export type StaleProvisional =
  | {
      [K in keyof ProvisionalResponses]: K extends `${infer M extends Method} ${infer P extends ApiPath}`
        ? [SpecResponse<Operation<P, M>>] extends [never]
          ? never
          : K
        : K;
    }[keyof ProvisionalResponses]
  | {
      [K in keyof ProvisionalBodies]: K extends `${infer M extends Method} ${infer P extends ApiPath}`
        ? [SpecBody<Operation<P, M>>] extends [never]
          ? never
          : K
        : K;
    }[keyof ProvisionalBodies];
const staleProvisional: [StaleProvisional] extends [never] ? true : StaleProvisional = true;
void staleProvisional;

/** Provisional entries for operations the document does not have. Must stay `never`. */
export type UnknownProvisional = Exclude<
  keyof ProvisionalResponses | keyof ProvisionalBodies,
  { [M in Method]: `${M} ${PathsWith<M>}` }[Method]
>;
const unknownProvisional: [UnknownProvisional] extends [never] ? true : UnknownProvisional = true;
void unknownProvisional;

/** `{id}`-style parameter names of a path template. */
export type PathParamNames<S extends string> = S extends `${string}{${infer N}}${infer R}` ? N | PathParamNames<R> : never;

type QueryValue = string | number | boolean | null | undefined | readonly (string | number)[];
export type Query = Record<string, QueryValue>;

interface CommonOptions {
  query?: Query | undefined;
  headers?: Record<string, string> | undefined;
  signal?: AbortSignal | undefined;
}

type PathOption<P extends string> = [PathParamNames<P>] extends [never]
  ? { path?: undefined }
  : { path: Record<PathParamNames<P>, string | number> };

export type GetOptions<P extends string> = CommonOptions & PathOption<P>;
export type WriteOptions<P extends string, B> = CommonOptions &
  PathOption<P> & {
    body?: B | FormData | Blob | undefined;
    ifMatch?: Revision | undefined;
    /** The key of one logical operation; null sends none (large uploads, see the import). */
    idempotencyKey?: string | null | undefined;
  };

type Optional<P extends string, T> = [PathParamNames<P>] extends [never] ? [options?: T] : [options: T];

/** Called once for a 401 so the session store can send the user to the sign-in page. */
let onUnauthorized: ((err: ApiError) => void) | undefined;
export function setUnauthorizedHandler(handler: ((err: ApiError) => void) | undefined): void {
  onUnauthorized = handler;
}

/** What a refused write sent, for [`setNoQuorumHandler`]. */
export interface SentWrite {
  method: Method;
  url: string;
  body: unknown;
  ifMatch: Revision | undefined;
}

let onNoQuorum: ((err: ApiError, write: SentWrite) => void) | undefined;

/** Called for every write refused with 503 `cluster.no_quorum` (an isolated controller, OPS-26); the error is still thrown. */
export function setNoQuorumHandler(handler: ((err: ApiError, write: SentWrite) => void) | undefined): void {
  onNoQuorum = handler;
}

let onStaleness: ((value: string | null) => void) | undefined;

/** Called with the `Tenko-Staleness` header of every answer, `null` when absent. */
export function setStalenessHandler(handler: ((value: string | null) => void) | undefined): void {
  onStaleness = handler;
}

export function newIdempotencyKey(): string {
  const c = globalThis.crypto;
  if (typeof c?.randomUUID === "function") return c.randomUUID();
  const b = new Uint8Array(16);
  c.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/** Fills `{name}` placeholders, percent-encoding each value as one path segment. */
export function buildPath(template: string, params: Record<string, string | number> | undefined, query?: Query): string {
  const path = template.replace(/\{([^}]+)\}/g, (_, name: string) => {
    const v = params?.[name];
    if (v === undefined) throw new Error(`missing path parameter ${name} for ${template}`);
    return encodeURIComponent(String(v));
  });
  const qs = query ? queryString(query) : "";
  return qs ? `${path}?${qs}` : path;
}

export function queryString(query: Query): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) {
      if (v.length) sp.set(k, v.join(","));
    } else sp.set(k, String(v));
  }
  return sp.toString();
}

function retryAfterSeconds(res: Response): number | undefined {
  const h = res.headers.get("retry-after");
  if (!h) return undefined;
  const n = Number(h);
  if (Number.isFinite(n)) return n;
  const at = Date.parse(h);
  return Number.isNaN(at) ? undefined : Math.max(0, Math.round((at - Date.now()) / 1000));
}

async function readBody(res: Response): Promise<unknown> {
  if (res.status === 204 || res.status === 205) return undefined;
  const type = res.headers.get("content-type") ?? "";
  if (type.includes("json")) {
    const text = await res.text();
    return text ? JSON.parse(text) : undefined;
  }
  return res.text();
}

/**
 * Performs one request with an untyped path. For the API layer itself (pagination);
 * everything else uses `api.*`, which only accepts paths from the OpenAPI document.
 */
export interface RawOptions extends CommonOptions {
  path?: Record<string, string | number> | undefined;
  /** A JSON value, or a FormData or Blob (a File too), which are sent as they are. */
  body?: unknown;
  ifMatch?: Revision | undefined;
  idempotencyKey?: string | null | undefined;
}

export async function rawRequest<T>(method: Method, template: string, options: RawOptions = {}): Promise<T> {
  return (await rawExchange<T>(method, template, options)).value;
}

/** `rawRequest` that also returns the `ETag` header of the answer, quotes removed, `null` when absent. */
export async function rawExchange<T>(
  method: Method,
  template: string,
  options: RawOptions = {},
): Promise<{ value: T; etag: Revision | null }> {
  const url = buildPath(template, options.path, options.query);
  const headers: Record<string, string> = { Accept: "application/json", ...options.headers };
  let body: BodyInit | undefined;
  if (options.body instanceof FormData) body = options.body;
  else if (options.body instanceof Blob) {
    headers["Content-Type"] = options.body.type || "application/octet-stream";
    body = options.body;
  } else if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }
  if (method === "post" && options.idempotencyKey !== null) {
    headers["Idempotency-Key"] = options.idempotencyKey ?? newIdempotencyKey();
  }
  if (method !== "get" && options.ifMatch !== undefined) {
    headers["If-Match"] = options.ifMatch === ANY_REVISION ? ANY_REVISION : `"${options.ifMatch}"`;
  }

  let res: Response;
  try {
    res = await fetch(url, {
      method: method.toUpperCase(),
      headers,
      body: body ?? null,
      credentials: "same-origin",
      signal: options.signal ?? null,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError({ status: 0, code: CLIENT_CODES.network, title: "", detail: String(err) });
  }

  onStaleness?.(res.headers.get("tenko-staleness"));
  let parsed: unknown;
  try {
    parsed = await readBody(res);
  } catch (err) {
    // A read cut short by the caller's abort is an abort, not an empty answer.
    if (options.signal?.aborted) throw err instanceof DOMException && err.name === "AbortError" ? err : new DOMException("The operation was aborted.", "AbortError");
    parsed = undefined;
  }
  if (!res.ok) {
    const err = new ApiError(toProblem(res.status, parsed), retryAfterSeconds(res));
    // A missing or expired session, not a failed sign-in attempt.
    if (res.status === 401 && (err.code === "auth.unauthenticated" || err.code === "auth.session_expired")) {
      onUnauthorized?.(err);
    }
    if (res.status === 503 && err.code === "cluster.no_quorum" && method !== "get") {
      onNoQuorum?.(err, {
        method,
        url,
        body: options.body instanceof FormData || options.body instanceof Blob ? undefined : options.body,
        ifMatch: options.ifMatch,
      });
    }
    throw err;
  }
  const etag = res.headers.get("etag");
  return { value: parsed as T, etag: etag === null ? null : etag.replace(/^W\//, "").replace(/^"(.*)"$/, "$1") };
}

/** The API, one method per HTTP verb. */
export const api = {
  get<P extends PathsWith<"get">>(path: P, ...[options]: Optional<P, GetOptions<P>>): Promise<ResponseOf<"get", P>> {
    return rawRequest("get", path, options as never);
  },
  /** `get` plus the `ETag` of the answer without its quotes (the revision to send back as `ifMatch`), `null` when absent. */
  getWithEtag<P extends PathsWith<"get">>(
    path: P,
    ...[options]: Optional<P, GetOptions<P>>
  ): Promise<{ value: ResponseOf<"get", P>; etag: Revision | null }> {
    return rawExchange("get", path, options as never);
  },
  post<P extends PathsWith<"post">>(
    path: P,
    ...[options]: Optional<P, WriteOptions<P, BodyOf<"post", P>>>
  ): Promise<ResponseOf<"post", P>> {
    return rawRequest("post", path, options as never);
  },
  put<P extends PathsWith<"put">>(
    path: P,
    ...[options]: Optional<P, WriteOptions<P, BodyOf<"put", P>>>
  ): Promise<ResponseOf<"put", P>> {
    return rawRequest("put", path, options as never);
  },
  patch<P extends PathsWith<"patch">>(
    path: P,
    ...[options]: Optional<P, WriteOptions<P, BodyOf<"patch", P>>>
  ): Promise<ResponseOf<"patch", P>> {
    return rawRequest("patch", path, options as never);
  },
  delete<P extends PathsWith<"delete">>(
    path: P,
    ...[options]: Optional<P, WriteOptions<P, never>>
  ): Promise<ResponseOf<"delete", P>> {
    return rawRequest("delete", path, options as never);
  },
};
