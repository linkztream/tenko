// The findings of the mock API: `GET /api/v1/findings` and `GET /api/v1/findings/counts` (docs/reconciliation.md section
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
import { mockFindingCounts, mockFindings, type MockFinding } from "./findings-store";
import { ok, Problem } from "./reply";
import { route } from "./route";

const counts = route("get", "/api/v1/findings/counts", () => {
  requireSession();
  return ok(mockFindingCounts());
});

/** The values of a list filter: the parameter repeated or comma separated. */
function filterValues(url: URL, name: string): Set<string> | null {
  const values = url.searchParams.getAll(name).flatMap((v) => v.split(",")).filter(Boolean);
  return values.length > 0 ? new Set(values) : null;
}

/** Whether a finding is about the prefix `id`: its subject's prefix, or an object of its subject. */
function inPrefix(finding: MockFinding, id: string): boolean {
  return finding.subject.prefix === id || (finding.subject.objects ?? []).some((o) => o.kind === "prefix" && o.id === id);
}

/** Whether the text is in the summary, the subject or the code, without case. */
function hasText(finding: MockFinding, text: string): boolean {
  const q = text.toLowerCase();
  return [finding.summary, finding.subject.label, finding.code].some((v) => v.toLowerCase().includes(q));
}

// The list the start page's strip (U3), the Discovery list and the reconciliation view (U4) read,
// with the filters of severity, kind, subject, area and source, `prefix` (the findings about a
// prefix: its subject's prefix, simplified) and `q`, and the page size; one page, no cursor (the
// mock never holds more than a page).
const list = route("get", "/api/v1/findings", (ctx) => {
  requireSession();
  const filters = (["severity", "kind", "area", "source"] as const).map((name) => [name, filterValues(ctx.url, name)] as const);
  const subjects = filterValues(ctx.url, "subject");
  const prefix = ctx.url.searchParams.get("prefix");
  const q = ctx.url.searchParams.get("q")?.trim();
  const limit = Math.min(1000, Math.max(1, Number(ctx.url.searchParams.get("limit") ?? 100) || 100));
  const items = mockFindings().filter(
    (f) =>
      filters.every(([name, values]) => !values || values.has(f[name])) &&
      (!subjects || subjects.has(f.subject.kind)) &&
      (!prefix || inPrefix(f, prefix)) &&
      (!q || hasText(f, q)),
  );
  return ok({ items: items.slice(0, limit), next_cursor: null, revision: db.revision });
});

// U4: one finding, for the side panel of a finding opened by its link.
const one = route("get", "/api/v1/findings/{id}", (ctx) => {
  requireSession();
  const id = decodeURIComponent(String(ctx.params.id));
  const found = mockFindings().find((f) => f.id === id);
  if (!found) throw new Problem("findings.not_found", { status: 404, detail: `no finding ${id}`, params: { id } });
  return ok(found);
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

export const findingsRoutes: HttpHandler[] = [counts, list, one];
