// The findings of the mock API: `GET /api/v1/findings/counts` (docs/reconciliation.md section
// 12.4), which every signed-in account may read, and the live topic `findings`.
//
// The server publishes a `findings.changed` event after its index applied a change of a
// proposal, an alarm or a job. The mock derives the counts on every read (findings-store.ts), so
// it publishes the event whenever such a source changes: on an event of the topic `ipam` or
// `jobs`, and on a prefix alarm (an event of the topic `system`). The event carries the
// proposals, prefixes and jobs of the source event and, as the server's, no id (it is not
// replayed) and `params.revision`, the revision the counts were read at. Simplification: the
// counts are scoped to nobody; every principal counts everything.
import type { HttpHandler } from "msw";
import { requireSession } from "./auth";
import { db, recordAlarm, subscribeEvents } from "./db";
import { mockFindingCounts } from "./findings-store";
import { ok } from "./reply";
import { route } from "./route";

const counts = route("get", "/api/v1/findings/counts", () => {
  requireSession();
  return ok(mockFindingCounts());
});

const KINDS = new Set(["proposal", "prefix", "job"]);

// Subscribed once, when the module loads. The event it publishes is of the topic `findings`,
// which it never answers, so it cannot loop.
subscribeEvents((event) => {
  const relevant = event.topic === "ipam" || event.topic === "jobs" || (event.topic === "system" && event.data.kind === "ipam.prefix.alarm");
  if (!relevant) return;
  recordAlarm("findings", {
    kind: "findings.changed",
    objects: event.data.objects.filter((ref) => KINDS.has(ref.kind)),
    params: { revision: String(db.revision) },
  });
});

export const findingsRoutes: HttpHandler[] = [counts];
