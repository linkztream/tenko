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
import { reconcileRoutes } from "./routes-reconcile";
import { revealPolicyRoutes } from "./routes-reveal-policy";
import { secretsRoutes } from "./routes-secrets";
import { systemRoutes } from "./routes-system";
import { updatesRoutes } from "./routes-updates";
import { eventRoutes } from "./sse";
import { stubs } from "./stubs";
import { nodeRoutes } from "./routes-nodes";
import { connectorRoutes } from "./routes-connectors";

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
  // Operator secrets (WP2.1), and TGL-24, which decorates the security settings that the
  // updates routes decorate with TGL-23, so it comes first.
  ...secretsRoutes,
  ...revealPolicyRoutes,
  // Updates and modules come before the admin and system routes: they decorate the security
  // settings with TGL-23 and answer the health probe with the version that runs.
  ...updatesRoutes,
  ...adminRoutes,
  ...systemRoutes,
  ...eventRoutes,
  ...reconcileRoutes,
  // Cluster nodes and enrolment tokens (WP2.2 routes, WP2.9 mock).
  ...nodeRoutes,
  ...connectorRoutes,
];

export const handlers: HttpHandler[] = [...happyPaths, ...stubs];
