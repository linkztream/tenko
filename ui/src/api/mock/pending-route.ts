// Mock handlers for pending operations: the routes `api/pending.ts` types before the OpenAPI
// document describes them. `route()` only accepts paths of the document; `pendingRoute()`
// accepts the paths of `PendingOperations` and gives the handler the same context, typed by
// the pending entry. When the document gains the operation, the area deletes the entry (the
// type check of pending.ts insists) and the handler moves to `route()` unchanged apart from
// the name.
import type { HttpHandler } from "msw";
import type { Method, PathParamNames } from "../client";
import type { PendingBody, PendingPaths, PendingResponse } from "../pending";
import type { Reply } from "./reply";
import { route, type Loose, type MockContext } from "./route";

type Awaitable<T> = T | Promise<T>;

/** The context of a pending handler: `route()`'s, with params and body of the pending entry. */
export interface PendingMockContext<M extends Method, P extends string>
  extends Omit<MockContext<M, never>, "params" | "body" | "optionalBody"> {
  readonly params: Record<PathParamNames<P>, string>;
  /** The JSON object of the body; a missing or malformed body fails with `sys.invalid_request`. */
  body(): Promise<Loose<PendingBody<M, P>>>;
  /** Like `body`, but an empty body is an empty object. */
  optionalBody(): Promise<Loose<PendingBody<M, P>>>;
}

/** Registers a handler for a pending operation. */
export function pendingRoute<M extends Method, P extends PendingPaths<M>>(
  method: M,
  path: P,
  resolver: (ctx: PendingMockContext<M, P>) => Awaitable<Reply<PendingResponse<M, P>> | Response>,
): HttpHandler {
  // route() checks the path against the document only in its type; at run time it registers
  // any path, which is what a pending operation needs.
  return route(method as never, path as never, resolver as never);
}

/** The context of a loose handler: path parameters and bodies as plain records. */
export interface LooseMockContext extends Omit<MockContext<Method, never>, "params" | "body" | "optionalBody"> {
  readonly params: Record<string, string>;
  body(): Promise<Record<string, unknown>>;
  optionalBody(): Promise<Record<string, unknown>>;
}

/**
 * Registers a handler for an operation the document describes whose mock still answers the
 * working model of its area (WP3.11c moves the last ones to `route()` with the generated types).
 */
export function looseRoute(
  method: Method,
  path: string,
  resolver: (ctx: LooseMockContext) => Awaitable<Reply<unknown> | Response>,
): HttpHandler {
  return route(method as never, path as never, resolver as never);
}
