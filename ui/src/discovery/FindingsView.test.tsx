// The findings list of Discovery (U4): every kind in one table grouped by severity (act now, review,
// info), 23 identical ghost rows as one closed group that says the rule once, the default action of
// each row calling the route its finding names, the side panel of a proposal and of a row of the
// reconciliation view (the conflict leading with both MAC addresses), the filters in the URL, and
// the facts of the header equal to the rail badge and the status bar after events out of order.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { createSignal } from "solid-js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ApiEvent, ConnectionState, EventStream, Topic } from "../api/events";
import type { components } from "../api/generated/schema";
import { HOST_IDS, IPAM_IDS } from "../api/mock/ipam/api";
import { server } from "../api/mock/node";
import { RECONCILE_IDS } from "../api/mock/reconcile-store";
import { setMockViewFindings, setMockViewRows } from "../api/mock/reconcile-view";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { resetGroupStateForTest } from "../grid/groups";
import { applied, confirmPlan, recordWrites } from "../ipam/testkit";
import FindingsStatus from "../shell/FindingsStatus";
import { useFindingCounts, type FindingCounts, type LevelCounts } from "../shell/findings";
import { Rail } from "../shell/Rail";
import * as badges from "../shell/railBadge";
import FindingsView, { panelTargetOf } from "./FindingsView";
import { resetRefs } from "./refs";

type Row = components["schemas"]["ReconcileRow"];

const P = RECONCILE_IDS.proposal;
const DAY = 24 * 3600 * 1000;
const iso = (ms: number) => new Date(ms).toISOString();

beforeEach(async () => {
  resetRefs();
  resetGroupStateForTest();
  await signInAlex();
});

afterEach(() => {
  setSessionForTest(null);
});

function renderList(url: string = paths.discovery()) {
  return renderRoute(FindingsView, {
    url,
    path: "/discovery/:id?",
    routes: {
      "/jobs/:id": () => <div data-testid="job-route" />,
      "/ipam/prefixes/*rest": () => <div data-testid="prefix-route" />,
    },
  });
}

const grid = () => screen.getByRole("grid", { name: "Findings" });
const lines = () => within(grid()).queryAllByTestId("row");
const groupRows = () => lines().filter((r) => r.dataset.expanded !== undefined);
const groupOf = (key: string) => groupRows().find((r) => r.dataset.key === `group:${key}`);
const findingRows = () => lines().filter((r) => r.dataset.expanded === undefined);
const rowOf = (id: string) => {
  const row = findingRows().find((r) => r.dataset.id === id);
  if (!row) throw new Error(`no row for finding ${id}`);
  return row;
};

/** 23 ghost addresses of managed hosts, none seen for a day: intent wins for every one. */
function ghosts(count: number, days = 1): Row[] {
  const now = Date.now();
  return Array.from({ length: count }, (_, i) => ({
    key: `192.0.2.${100 + i}|ghost`,
    kind: "ghost" as const,
    address: `192.0.2.${100 + i}`,
    vrf: IPAM_IDS.vrf.default,
    prefix: IPAM_IDS.prefix.lan,
    intent: { host_name: `ghost-${i}`, mode: "reserved" as const, status: "active" as const, macs: [] },
    macs: [],
    vendors: [],
    winner: "intent" as const,
    rule_id: "intent_managed" as const,
    rule: "intent wins for a managed host",
    last_seen: iso(now - days * DAY - i * 60_000),
  }));
}

describe("the findings list", () => {
  it("lists every kind in one table, grouped by severity with the conflict to act on first", async () => {
    setMockViewFindings(true);
    renderList();
    await waitFor(() => expect(groupRows().length).toBe(3));
    expect(groupRows().map((r) => r.dataset.key)).toEqual(["group:act", "group:review", "group:info"]);
    // The first row after the act group is a conflict, with its MACs as its evidence.
    const first = lines()[1] as HTMLElement;
    expect(first.querySelector("[data-kind]")?.getAttribute("data-kind")).toBe("conflict");
    expect(first.classList.contains("conflict")).toBe(true);
    // A proposal, a row of the view and a waiting job are all listed.
    expect(findingRows().some((r) => r.dataset.id === `proposal:${P.mediaPc}`)).toBe(true);
    expect(findingRows().some((r) => r.dataset.id?.startsWith("reconcile:"))).toBe(true);
    // Every row is a row of the grid, 28 px by the grid's density; no cell is filled green.
    expect(document.querySelector(".tag.ok, .ok-wash")).toBeNull();
    expect(await axeViolations(screen.getByTestId("page-discovery"))).toEqual([]);
  });

  it("draws 23 identical ghost rows as one closed group that says the rule once", async () => {
    setMockViewFindings(true);
    setMockViewRows(ghosts(23));
    renderList();
    await waitFor(() => expect(groupOf("info")).toBeTruthy());
    const info = groupOf("info") as HTMLElement;
    expect(info.dataset.expanded).toBe("false");
    expect(within(info).getByTestId("group-count").textContent).toBe("23");
    expect(within(info).getByTestId("group-sentence").textContent).toBe("Intent wins: the host is managed, so what intent says stands.");
    expect(screen.getAllByText("Intent wins: the host is managed, so what intent says stands.")).toHaveLength(1);
    expect(findingRows().filter((r) => r.dataset.id?.startsWith("reconcile:"))).toHaveLength(0);
    // Opened, the rows carry the evidence and not the sentence.
    fireEvent.click(within(info).getByRole("button"));
    await waitFor(() => expect(findingRows().filter((r) => r.dataset.id?.startsWith("reconcile:")).length).toBeGreaterThan(5));
    expect(screen.getAllByText("Intent wins: the host is managed, so what intent says stands.")).toHaveLength(1);
  });

  it("keeps an Info group of ten rows or fewer open", async () => {
    setMockViewFindings(true);
    setMockViewRows(ghosts(4));
    renderList();
    await waitFor(() => expect(groupOf("info")?.dataset.expanded).toBe("true"));
  });

  it("filters by severity and kind with chips that keep the URL, each kind chip with its count", async () => {
    setMockViewFindings(true);
    const view = renderList();
    await waitFor(() => expect(groupRows().length).toBe(3));
    const conflicts = screen.getByTestId("filter-kind-conflict");
    expect(within(conflicts).getByTestId("chip-count").textContent).toBe("3");
    fireEvent.click(conflicts);
    await waitFor(() => expect(view.location()).toContain("kind=conflict"));
    await waitFor(() => expect(groupRows().map((r) => r.dataset.key)).toEqual(["group:act"]));
    // The kind is said once in the header now that every row shares it.
    const kindHeader = within(grid()).getAllByRole("columnheader").find((h) => h.dataset.col === "kind");
    expect(kindHeader?.textContent).toBe("Kind · Conflict");
    fireEvent.click(screen.getByTestId("filter-severity-review"));
    await waitFor(() => expect(view.location()).toContain("severity=review"));
  });

  it("takes the severity of the status bar's links from the URL", async () => {
    setMockViewFindings(true);
    renderList(paths.discovery({ severity: "act" }));
    await waitFor(() => expect(groupRows().map((r) => r.dataset.key)).toEqual(["group:act"]));
    expect(screen.getByTestId("filter-severity-act").getAttribute("aria-pressed")).toBe("true");
  });

  it("says that nothing needs a decision when nothing is found", async () => {
    server.use(http.get("*/api/v1/findings", () => HttpResponse.json({ items: [], next_cursor: null, revision: 1 })));
    renderList();
    expect((await screen.findByTestId("discovery-empty")).textContent).toContain("Nothing needs a decision");
  });
});

describe("the default action of a row", () => {
  it("adopts an unknown device through the plan dialog of its proposal", async () => {
    const calls = recordWrites();
    renderList();
    await waitFor(() => expect(findingRows().length).toBeGreaterThan(0));
    const action = within(rowOf(`proposal:${P.mediaPc}`)).getByTestId("finding-action");
    expect(action.textContent).toBe("Adopt");
    fireEvent.click(action);
    await confirmPlan({ dialog: "dialog-approve" });
    await waitFor(() => expect(applied(calls()).some((c) => c.method === "POST" && c.url.includes(`/api/v1/proposals/${P.mediaPc}/approve`))).toBe(true));
  });

  it("resolves a conflict in the side panel, which leads with both MAC addresses", async () => {
    const view = renderList();
    await waitFor(() => expect(findingRows().length).toBeGreaterThan(0));
    const action = within(rowOf(`proposal:${P.printerTaken}`)).getByTestId("finding-action");
    expect(action.textContent).toBe("Resolve");
    fireEvent.click(action);
    await waitFor(() => expect(view.location()).toBe(paths.proposal(P.printerTaken)));
    const lead = await screen.findByTestId("conflict-lead");
    expect(within(lead).getAllByTestId("conflict-mac").map((m) => m.dataset.mac)).toEqual(["00:00:5e:00:53:1e", "00:00:5e:00:53:b0"]);
    // The panel offers the choices as buttons, keep both among them.
    expect(await screen.findByTestId("conflict-keep")).toBeTruthy();
    expect(screen.getByTestId("discovery-reject").textContent).toContain("Dismiss");
  });

  it("decommissions the host of a ghost unseen for longer than the age", async () => {
    setMockViewFindings(true);
    setMockViewRows([{ ...ghosts(1, 40)[0]!, host: HOST_IDS["ap-garage"]!, intent: { host: HOST_IDS["ap-garage"]!, host_name: "ap-garage", mode: "reserved", status: "active", macs: [] } }]);
    const calls = recordWrites();
    renderList();
    await waitFor(() => expect(groupOf("review")).toBeTruthy());
    const row = findingRows().find((r) => r.dataset.id?.startsWith("reconcile:")) as HTMLElement;
    const action = within(row).getByTestId("finding-action");
    expect(action.textContent).toBe("Decommission");
    fireEvent.click(action);
    const choice = await screen.findByTestId("dialog-decommission");
    fireEvent.click(within(choice).getByTestId("form-submit"));
    await confirmPlan({ dialog: "dialog-decommission-plan" });
    await waitFor(() => expect(applied(calls()).some((c) => c.method === "POST" && c.url.includes(`/api/v1/hosts/${HOST_IDS["ap-garage"]}/decommission`))).toBe(true));
  });

  it("links a waiting job, a network over its alarm, a PTR to fix and a health condition to where they are done", async () => {
    setMockViewFindings(true);
    const findings = [
      { id: "job:j1", kind: "job_waiting", severity: "act", area: "jobs", subject: { kind: "job", label: "ipam.move", objects: [] }, summary: "waits", code: "ipam.move", params: { step: "1", title: "ipam.move" }, evidence: { id: "0190d1c2-0000-7000-8000-00000000j001", path: "/jobs/x" }, action: "open_manual_step", since: iso(Date.now()), source: "job" },
      { id: "alarm:p1", kind: "utilization", severity: "act", area: "ipam", subject: { kind: "prefix", label: "198.51.100.0/24", cidr: "198.51.100.0/24", objects: [] }, summary: "full", code: "ipam.prefix.alarm.critical", params: { percent: "96.5", threshold: "90" }, evidence: { id: "p1", path: "/prefixes/p1" }, action: "open_prefix", since: iso(Date.now()), source: "alarm" },
      { id: "reconcile:ptr", kind: "ptr_mismatch", severity: "review", area: "dns", subject: { kind: "address", label: "192.0.2.30", ip: "192.0.2.30", objects: [] }, summary: "ptr", code: "ipam.reconcile.view.ptr_mismatch", params: { ptr: "printer.example.test", rule: "intent_managed" }, evidence: { id: "192.0.2.30|ptr_mismatch", path: "/ipam/reconcile" }, action: "fix_ptr", since: iso(Date.now()), source: "reconcile" },
      { id: "health:h1", kind: "health", severity: "review", area: "nodes", subject: { kind: "node", label: "node.disk.low", objects: [] }, summary: "Low disk", code: "node.disk.low", params: {}, evidence: { id: "node.disk.low", path: "/system/status" }, action: "open_status", since: iso(Date.now()), source: "health" },
    ];
    server.use(http.get("*/api/v1/findings", () => HttpResponse.json({ items: findings, next_cursor: null, revision: 1 })));
    renderList();
    await waitFor(() => expect(findingRows()).toHaveLength(4));
    const link = (id: string) => within(rowOf(id)).getByTestId("finding-action");
    expect(link("job:j1").getAttribute("href")).toBe(paths.job("0190d1c2-0000-7000-8000-00000000j001"));
    expect(link("job:j1").textContent).toBe("Open the job");
    expect(link("alarm:p1").getAttribute("href")).toBe(paths.prefix("198.51.100.0/24"));
    expect(within(rowOf("alarm:p1")).getByTestId("finding-evidence").textContent).toBe("96.5 % in use, over the alarm at 90 %");
    expect(link("reconcile:ptr").getAttribute("href")).toBe(paths.address("192.0.2.30"));
    expect(link("reconcile:ptr").textContent).toBe("Fix PTR");
    expect(link("health:h1").getAttribute("href")).toBe(paths.nodes());
  });

  it("opens a job's finding on its job instead of a panel", async () => {
    const findings = [
      { id: "job:j1", kind: "job_waiting", severity: "act", area: "jobs", subject: { kind: "job", label: "ipam.move", objects: [] }, summary: "waits", code: "ipam.move", params: { step: "0" }, evidence: { id: "0190d1c2-0000-7000-8000-00000000j001", path: "/jobs/x" }, action: "open_manual_step", since: iso(Date.now()), source: "job" },
    ];
    server.use(http.get("*/api/v1/findings", () => HttpResponse.json({ items: findings, next_cursor: null, revision: 1 })));
    const view = renderList();
    await waitFor(() => expect(findingRows()).toHaveLength(1));
    fireEvent.click(rowOf("job:j1").querySelector("[data-col='evidence']") as HTMLElement);
    await waitFor(() => expect(view.location()).toBe(paths.job("0190d1c2-0000-7000-8000-00000000j001")));
  });
});

describe("the side panel of a row of the reconciliation view", () => {
  it("shows the four truths with the winner's check glyph, the rule, and the link to the view", async () => {
    setMockViewFindings(true);
    const view = renderList();
    await waitFor(() => expect(findingRows().length).toBeGreaterThan(0));
    const conflict = findingRows().find((r) => r.dataset.id?.startsWith("reconcile:") && r.dataset.key === "192.0.2.44") as HTMLElement;
    fireEvent.click(conflict.querySelector("[data-col='evidence']") as HTMLElement);
    await waitFor(() => expect(view.location()).toContain("/discovery/reconcile:"));
    const panel = await screen.findByTestId("finding-panel");
    expect(within(panel).getByTestId("finding-title").textContent).toBe("Conflict on 192.0.2.44");
    await within(panel).findByTestId("truth-list");
    expect(within(panel).getAllByTestId("conflict-mac").map((m) => m.dataset.mac)).toEqual(["00:00:5e:00:53:2c", "00:00:5e:00:53:c8"]);
    expect(within(panel).getByTestId("finding-rule").textContent).toContain("Never resolved automatically");
    expect(within(panel).getByTestId("finding-reconcile-link").getAttribute("href")).toContain("/ipam/reconcile?prefix=");
    expect(await axeViolations(panel)).toEqual([]);
  });

  it("reads a finding of the URL by its id", () => {
    expect(panelTargetOf(P.mediaPc)).toEqual({ proposal: P.mediaPc });
    expect(panelTargetOf(`proposal:${P.mediaPc}`)).toEqual({ proposal: P.mediaPc });
    expect(panelTargetOf("reconcile%3Aabc")).toEqual({ findingId: "reconcile:abc" });
  });
});

// ---------------------------------------------------------------------------------------------
// One number on the header, the rail and the status bar (ui-plan section 2.5)

const ZERO: LevelCounts = { act: 0, review: 0, info: 0 };

function countsOf(revision: number, discovery: LevelCounts): FindingCounts {
  const areas = Object.fromEntries(["ipam", "dns", "dhcp", "discovery", "topology", "jobs", "connectors", "nodes", "settings"].map((a) => [a, a === "discovery" ? discovery : ZERO])) as FindingCounts["areas"];
  return { areas, revision, problems: discovery.act + discovery.review, total: discovery, sources: { alarm: 0, health: 0, job: 0, proposal: discovery.act + discovery.review, reconcile: 0 } };
}

function fakeStream() {
  const handlers = new Map<Topic, Set<(e: ApiEvent) => void>>();
  const [state] = createSignal<ConnectionState>("live");
  const stream = {
    state,
    subscribe(topic: Topic, handler: (e: ApiEvent) => void) {
      const set = handlers.get(topic) ?? new Set();
      handlers.set(topic, set);
      set.add(handler);
      return () => set.delete(handler);
    },
    onReset: () => () => undefined,
  };
  return {
    stream: stream as unknown as EventStream,
    emit(revision: number) {
      const event: ApiEvent = { topic: "findings", type: "findings", objects: [], deleted: [], revision: undefined, data: { kind: "findings.changed", params: { revision: String(revision) } } };
      for (const h of [...(handlers.get("findings") ?? [])]) h(event);
    },
  };
}

describe("one count on every surface", () => {
  it("shows one number in the header, the rail badge and the status bar after events and answers out of order", async () => {
    const waiting: { counts: FindingCounts; release: Promise<void> }[] = [];
    let reads = 0;
    server.use(
      http.get("*/api/v1/findings/counts", async () => {
        reads += 1;
        const next = waiting.shift();
        if (!next) return HttpResponse.json(countsOf(10, { act: 1, review: 2, info: 0 }));
        await next.release;
        return HttpResponse.json(next.counts);
      }),
    );
    const answer = (counts: FindingCounts) => {
      let release!: () => void;
      waiting.push({ counts, release: new Promise<void>((resolve) => (release = resolve)) });
      return release;
    };
    const fake = fakeStream();
    function Surfaces() {
      const counts = useFindingCounts(fake.stream);
      return (
        <>
          <Rail badges={badges} counts={counts()} />
          <footer class="statusbar">
            <FindingsStatus counts={counts()} />
          </footer>
          <FindingsView />
        </>
      );
    }
    renderRoute(Surfaces, { url: paths.discovery(), path: "/discovery/:id?" });
    const facts = () => screen.getByTestId("discovery-facts").textContent;
    const rail = () => document.querySelector(`.rail a[data-area="discovery"] [data-testid="rail-badge"]`)?.textContent;
    await waitFor(() => expect(facts()).toBe("1 to act on · 2 to review · 0 info"));
    expect(rail()).toBe("3");
    expect(screen.getByTestId("status-findings-act").textContent).toBe("1 act now");

    // Two events arrive out of order (12, then 11); the newer answer comes back first.
    const newer = answer(countsOf(12, { act: 2, review: 3, info: 4 }));
    fake.emit(12);
    fake.emit(11);
    await waitFor(() => expect(reads).toBeGreaterThanOrEqual(2));
    newer();
    await waitFor(() => expect(facts()).toBe("2 to act on · 3 to review · 4 info"));
    expect(rail()).toBe("5");
    expect(screen.getByTestId("status-findings-act").textContent).toBe("2 act now");
    expect(screen.getByTestId("status-findings-review").textContent).toBe("3 to review");

    // A late answer of the older revision is dropped on every surface.
    const stale = answer(countsOf(11, { act: 9, review: 9, info: 9 }));
    fake.emit(11);
    await waitFor(() => expect(reads).toBeGreaterThanOrEqual(3));
    stale();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(facts()).toBe("2 to act on · 3 to review · 4 info");
    expect(rail()).toBe("5");
    expect(screen.getByTestId("status-findings-act").textContent).toBe("2 act now");
  });
});
