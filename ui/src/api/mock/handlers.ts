// Every handler of the mock API: the happy paths first, then one 501 stub per operation of
// the OpenAPI document. msw uses the first handler that answers, so a happy path wins over
// its stub. Register more with `route()`, which only accepts paths of the document.
import type { HttpHandler } from "msw";
import { adminRoutes } from "./routes-admin";
import { authRoutes } from "./routes-auth";
import { systemRoutes } from "./routes-system";
import { eventRoutes } from "./sse";
import { stubs } from "./stubs";

export { route, mswPath, paginate, wholePage, type MockContext, type OperationPath } from "./route";
export { ok, created, noContent, fail, Problem, Reply } from "./reply";

/** The handlers that answer for real. */
export const happyPaths: HttpHandler[] = [...authRoutes, ...adminRoutes, ...systemRoutes, ...eventRoutes];

export const handlers: HttpHandler[] = [...happyPaths, ...stubs];
