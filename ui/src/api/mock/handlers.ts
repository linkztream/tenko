// Every handler of the mock API: the happy paths first, then one 501 stub per operation of
// the OpenAPI document. msw uses the first handler that answers, so a happy path wins over
// its stub. Register more with `route()`, which only accepts paths of the document.
import type { HttpHandler } from "msw";
import { ipamRoutes } from "./ipam/routes";
import { accessRoutes } from "./routes-access";
import { adminRoutes } from "./routes-admin";
import { auditRoutes } from "./routes-audit";
import { auditExportRoutes } from "./routes-audit-export";
import { authRoutes } from "./routes-auth";
import { backupRoutes } from "./routes-backup";
import { guardrailsRoutes } from "./routes-guardrails";
import { tlsRoutes } from "./routes-tls";
import { nameAuthorityRoutes } from "./name-authority";
import { reconcilerRoutes } from "./routes-reconciler";
import { clusterRoutes, quorumGate } from "./routes-cluster";
import { i18nRoutes } from "./routes-i18n";
import { importRoutes } from "./routes-import";
import { jobRoutes } from "./routes-jobs";
import { kekRoutes } from "./routes-kek";
import { moveRoutes } from "./routes-move";
import { reconcileRoutes } from "./routes-reconcile";
import { ipamReconcileRoutes } from "./routes-ipam-reconcile"; // WP8.2
import { revealPolicyRoutes } from "./routes-reveal-policy";
import { scansRoutes } from "./routes-scans";
import { secretsRoutes } from "./routes-secrets";
import { systemRoutes } from "./routes-system";
import { topologyRoutes } from "./routes-topology";
import { updatesRoutes } from "./routes-updates";
import { vlanRoutes } from "./routes-vlans";
import { eventRoutes } from "./sse";
import { stubs } from "./stubs";
import { nodeRoutes } from "./routes-nodes";
import { connectorRoutes } from "./routes-connectors";
import { dnsRoutes } from "./routes-dns";
// WP7.4
import { dhcpRoutes } from "./routes-dhcp";
// WP7.5: the leases, the history and the state of the dhcp role of a node.
import { dhcpLeaseRoutes } from "./routes-dhcp-leases";
// Reserving an address in DHCP: the IPAM rows of a reservation in one plan.
import { reserveRoutes } from "./routes-reserve";
// U1: the counts of the findings model and its live topic.
import { findingsRoutes } from "./routes-findings";

export { route, mswPath, paginate, wholePage, type MockContext, type OperationPath } from "./route";
export { ok, created, noContent, fail, Problem, Reply } from "./reply";

/** The handlers that answer for real. IPAM, jobs and audit come first: they replace the
 * shell's early stand-ins for search and the job list. */
export const happyPaths: HttpHandler[] = [
  // The quorum gate answers 503 to a write while the controller is isolated, before any write handler.
  ...quorumGate,
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
  ...ipamReconcileRoutes, // WP8.2
  // Cluster nodes and enrolment tokens (WP2.2 routes, WP2.9 mock).
  ...nodeRoutes,
  ...connectorRoutes,
  // The topology map, the VLAN provision and the prefixes of a VLAN (WP2.7).
  ...topologyRoutes,
  ...vlanRoutes,
  // The API areas of Slice 3: empty files that the UI packages fill as the Rust packages add
  // their operations (WP3.0).
  ...clusterRoutes,
  ...scansRoutes,
  ...accessRoutes,
  ...auditExportRoutes,
  ...kekRoutes,
  ...backupRoutes,
  ...reconcilerRoutes,
  ...nameAuthorityRoutes,
  ...guardrailsRoutes,
  ...tlsRoutes,
  ...i18nRoutes,
  // The DNS area of Phase 2 (WP4.5): zones, records, zone files, access lists and TSIG keys.
  ...dnsRoutes,
  // WP7.4: the DHCP configuration of Phase 3.
  ...dhcpRoutes,
  // WP7.5: the leases and the history, ahead of the 501 stubs.
  ...dhcpLeaseRoutes,
  ...reserveRoutes,
  // The findings counts (docs/reconciliation.md section 12), ahead of the 501 stubs.
  ...findingsRoutes,
];

export const handlers: HttpHandler[] = [...happyPaths, ...stubs];
