// Every handler of the mock API: the happy paths first, then one 501 stub per operation of
// the OpenAPI document. msw uses the first handler that answers, so a happy path wins over
// its stub. Register more with `route()`, which only accepts paths of the document.
import type { HttpHandler } from "msw";
import { ipamRoutes } from "./ipam/routes";
import { adminRoutes } from "./routes-admin";
import { auditRoutes } from "./routes-audit";
import { authRoutes } from "./routes-auth";
import { importRoutes } from "./routes-import";
import { jobRoutes } from "./routes-jobs";
import { moveRoutes } from "./routes-move";
import { systemRoutes } from "./routes-system";
import { updatesRoutes } from "./routes-updates";
import { eventRoutes } from "./sse";
import { stubs } from "./stubs";

export { route, mswPath, paginate, wholePage, type MockContext, type OperationPath } from "./route";
export { ok, created, noContent, fail, Problem, Reply } from "./reply";

/** The handlers that answer for real. IPAM, jobs and audit come first: they replace the
 * shell's early stand-ins for search and the job list. */
export const happyPaths: HttpHandler[] = [
  ...ipamRoutes,
  ...moveRoutes,
  ...importRoutes,
  ...jobRoutes,
  ...auditRoutes,
  ...authRoutes,
  // Updates and modules come before the admin and system routes: they decorate the security
  // settings with TGL-23 and answer the health probe with the version that runs.
  ...updatesRoutes,
  ...adminRoutes,
  ...systemRoutes,
  ...eventRoutes,
];

export const handlers: HttpHandler[] = [...happyPaths, ...stubs];
