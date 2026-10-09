// The typed way to register a mock handler. A path must be an operation of the OpenAPI
// document for the method (`apiOperations`), so a handler for a path that does not exist
// fails to compile; the reply is typed by the operation's response (the generated type, or
// the provisional one while the document has no schema).
import { http, type HttpHandler } from "msw";
import type { ApiPath, BodyOf, Method, PathParamNames, ResponseOf } from "../client";
import type { apiOperations } from "../generated/operations";
import type { Page } from "../types";
import { Problem, Reply, fail } from "./reply";

type Awaitable<T> = T | Promise<T>;
type Operation = (typeof apiOperations)[number];

/** The paths of the document that support `M`. */
export type OperationPath<M extends Method> = Extract<Operation, { readonly method: M }>["path"];

/** Converts a document path (`/users/{id}`) to an msw path (`/users/:id`). */
export function mswPath(path: string): string {
  return path.replace(/\{([^}]+)\}/g, ":$1");
}

/** A request body as received: an object whose members still have to be checked. */
export type Loose<T> = T extends object ? { [K in keyof T]?: unknown } : Record<string, unknown>;

export interface MockContext<M extends Method, P extends string> {
  readonly request: Request;
  readonly url: URL;
  readonly params: Record<PathParamNames<P>, string>;
  /** The JSON object of the body; a missing or malformed body fails with `sys.invalid_request`. */
  body(): Promise<Loose<BodyOf<M, P & ApiPath>>>;
  /** Like `body`, but an empty body is an empty object. */
  optionalBody(): Promise<Loose<BodyOf<M, P & ApiPath>>>;
  query(name: string): string | null;
  header(name: string): string | null;
  /** `If-Match`: a revision, `*`, or null when the header is absent. */
  ifMatch(): number | "*" | null;
}

function invalidBody(detail: string): never {
  return fail("sys.invalid_request", { detail });
}

async function readBody(request: Request, optional: boolean): Promise<Record<string, unknown>> {
  const text = await request.text();
  if (text.trim() === "") {
    if (optional) return {};
    return invalidBody("the request body is missing");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return invalidBody("the request body is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return invalidBody("the request body must be a JSON object");
  }
  return parsed as Record<string, unknown>;
}

function parseIfMatch(raw: string | null): number | "*" | null {
  if (raw === null) return null;
  const text = raw.trim();
  if (text === "*") return "*";
  const match = /^(?:W\/)?"?(\d+)"?$/.exec(text);
  if (!match) return fail("sys.invalid_value", { params: { name: "If-Match", value: raw } });
  return Number(match[1]);
}

/** Registers a handler for an operation of the document. */
export function route<M extends Method, P extends OperationPath<M>>(
  method: M,
  path: P,
  resolver: (ctx: MockContext<M, P>) => Awaitable<Reply<ResponseOf<M, P & ApiPath>> | Response>,
): HttpHandler {
  return http[method](mswPath(path), async ({ request, params }) => {
    const url = new URL(request.url);
    const flat: Record<string, string> = {};
    for (const [name, value] of Object.entries(params)) {
      flat[name] = Array.isArray(value) ? (value[0] ?? "") : String(value ?? "");
    }
    const ctx: MockContext<M, P> = {
      request,
      url,
      params: flat as Record<PathParamNames<P>, string>,
      body: () => readBody(request, false) as never,
      optionalBody: () => readBody(request, true) as never,
      query: (name) => url.searchParams.get(name),
      header: (name) => request.headers.get(name),
      ifMatch: () => parseIfMatch(request.headers.get("if-match")),
    };
    try {
      const result = await resolver(ctx);
      return result instanceof Reply ? result.toResponse() : result;
    } catch (error) {
      if (error instanceof Problem) return error.reply.toResponse();
      const detail = error instanceof Error ? error.message : String(error);
      return new Problem("sys.internal", { detail: `the mock handler failed: ${detail}` }).reply.toResponse();
    }
  });
}

// ---------------------------------------------------------------------------------
// Lists

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 1000;

/** Cuts a list into the page `limit` and `cursor` ask for (the cursor is an opaque offset). */
export function paginate<T>(items: readonly T[], url: URL, revision: number): Page<T> {
  const rawLimit = url.searchParams.get("limit");
  let limit = DEFAULT_LIMIT;
  if (rawLimit !== null) {
    limit = Number(rawLimit);
    if (!Number.isInteger(limit) || limit < 1) {
      fail("sys.invalid_query", { params: { name: "limit", value: rawLimit } });
    }
    limit = Math.min(limit, MAX_LIMIT);
  }
  let offset = 0;
  const cursor = url.searchParams.get("cursor");
  if (cursor) {
    try {
      offset = Number(atob(cursor.replace(/-/g, "+").replace(/_/g, "/")).replace(/^o/, ""));
    } catch {
      offset = Number.NaN;
    }
    if (!Number.isInteger(offset) || offset < 0) {
      fail("sys.invalid_cursor", { params: { cursor } });
    }
  }
  const end = offset + limit;
  const next =
    end < items.length ? btoa(`o${end}`).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") : null;
  return { items: items.slice(offset, end), next_cursor: next, revision };
}

/** A page with every item. */
export function wholePage<T>(items: readonly T[], revision: number): Page<T> {
  return { items: [...items], next_cursor: null, revision };
}
