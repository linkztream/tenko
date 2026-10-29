// The reconciliation view as the per-network evidence view (U4): one 28 px table grouped by
// severity, then kind, the conflict to act on first; the rule said once on a group row whose rows
// share it; the winning truth as a check glyph in its column and no fill; the four truths, the
// outcome, the OS field and the vendors; the side panel Discovery uses (a proposal's, or the row's
// truths); the scope filter (prefix and host) sent to every kind and to the findings; paging per
// kind and the error of one kind.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { components } from "../../api/generated/schema";
import { seedRows } from "../../api/mock/ipam-reconcile-model";
import { HOST_IDS, IPAM_IDS } from "../../api/mock/ipam/api";
import { server } from "../../api/mock/node";
import { RECONCILE_IDS } from "../../api/mock/reconcile-store";
import { setMockViewFindings, setMockViewRows } from "../../api/mock/reconcile-view";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { resetGroupStateForTest } from "../../grid/groups";
import { IpamNav } from "../IpamNav";
import ReconcileView, { defaultLevel } from "./ReconcileView";

type Row = components["schemas"]["ReconcileRow"];

let requests: Record<string, string>[] = [];
let findingRequests: URLSearchParams[] = [];

beforeEach(async () => {
  requests = [];
  findingRequests = [];
  resetGroupStateForTest();
  server.events.on("request:start", ({ request }) => {
    const url = new URL(request.url);
    if (url.pathname === "/api/v1/ipam/reconcile") requests.push(Object.fromEntries(url.searchParams));
    if (url.pathname === "/api/v1/findings") findingRequests.push(url.searchParams);
  });
  await signInAlex();
  // After the sign-in, which resets the mock: the rows of the view are findings here.
  setMockViewFindings(true);
});

afterEach(() => {
  server.events.removeAllListeners();
  setSessionForTest(null);
});

function renderView(url = "/ipam/reconcile") {
  return renderRoute(ReconcileView, {
    url,
    path: "/ipam/reconcile",
    routes: { "/discovery/:id": () => <div data-testid="proposal-route" /> },
  });
}

const grid = () => screen.getByRole("grid", { name: "Reconciliation" });
const lines = () => within(grid()).queryAllByTestId("row");
const groupRows = () => lines().filter((r) => r.dataset.expanded !== undefined);
const groupKeys = () => groupRows().map((r) => r.dataset.key?.replace(/^group:/, ""));
const dataRows = () => lines().filter((r) => r.dataset.expanded === undefined && !r.classList.contains("group-tail"));
const row = (key: string): HTMLElement => {
  const found = dataRows().find((r) => r.dataset.id === key);
  if (!found) throw new Error(`no row ${key}`);
  return found;
};
const cell = (r: HTMLElement, col: string) => r.querySelector(`td[data-col='${col}']`) as HTMLElement;

/** Renders the view and waits until every kind has answered and the rows are grouped. */
async function openView(url?: string, rows = 10) {
  const view = renderView(url);
  await waitFor(() => expect(dataRows()).toHaveLength(rows));
  return view;
}

const seed = () => seedRows({ vrf: IPAM_IDS.vrf.default, prefix: IPAM_IDS.prefix.lan, host: (n) => HOST_IDS[n] ?? n, proposal: RECONCILE_IDS.proposal.mediaPc });

describe("the table", () => {
  it("groups the rows by severity, then kind, with the conflicts to act on first", async () => {
    await openView();
    expect(groupKeys()).toEqual(["act:conflict", "review:rogue", "review:orphan", "review:ptr_mismatch", "info:rogue", "info:ghost"]);
    const act = groupRows()[0] as HTMLElement;
    expect(act.textContent).toContain("Act now");
    expect(act.textContent).toContain("Conflicts");
    expect(within(act).getByTestId("group-count").textContent).toBe("2");
    expect(within(act).getByTestId("group-note").textContent).toBe("Two devices on one address.");
    // The first row after it is a conflict, in the class of a conflict.
    expect((lines()[1] as HTMLElement).dataset.id).toBe("192.0.2.44|conflict");
    expect((lines()[1] as HTMLElement).classList.contains("conflict")).toBe(true);
    // The rogue with an open proposal is to review, the one whose proposal was decided is information.
    expect(row("192.0.2.150|rogue").closest("tr")).toBeTruthy();
    expect(defaultLevel({ kind: "rogue", proposal: "x" })).toBe("review");
    expect(defaultLevel({ kind: "rogue" })).toBe("info");
  });

  it("says the rule once on a group row whose rows all share it, and on none where they differ", async () => {
    await openView();
    const conflicts = groupRows()[0] as HTMLElement;
    expect(within(conflicts).getByTestId("group-sentence").textContent).toBe("Never resolved automatically: two devices on one address need a person to decide.");
    // The two ghosts are decided by two rules: no sentence on their group.
    const ghosts = groupRows().find((r) => r.dataset.key === "group:info:ghost") as HTMLElement;
    expect(within(ghosts).queryByTestId("group-sentence")).toBeNull();
  });

  it("draws 23 ghost addresses where intent wins as one closed group with the rule once", async () => {
    const now = Date.now();
    const ghosts: Row[] = Array.from({ length: 23 }, (_, i) => ({
      key: `192.0.2.${100 + i}|ghost`,
      kind: "ghost",
      address: `192.0.2.${100 + i}`,
      vrf: IPAM_IDS.vrf.default,
      prefix: IPAM_IDS.prefix.lan,
      intent: { host_name: `ghost-${i}`, mode: "reserved", status: "active", macs: [] },
      macs: [],
      vendors: [],
      winner: "intent",
      rule_id: "intent_managed",
      rule: "intent wins for a managed host",
      last_seen: new Date(now - 86_400_000).toISOString(),
    }));
    setMockViewRows([...seed().filter((r) => r.kind === "conflict"), ...ghosts]);
    renderView();
    await waitFor(() => expect(groupKeys()).toEqual(["act:conflict", "info:ghost"]));
    const group = groupRows()[1] as HTMLElement;
    expect(group.dataset.expanded).toBe("false");
    expect(within(group).getByTestId("group-count").textContent).toBe("23");
    expect(screen.getAllByText("Intent wins: the host is managed, so what intent says stands.")).toHaveLength(1);
    expect(dataRows()).toHaveLength(2);
    fireEvent.click(within(group).getByRole("button"));
    await waitFor(() => expect(dataRows()).toHaveLength(25));
    // Every ghost's outcome is the same, so the header says it once and the cells stay empty.
    const outcome = within(grid()).getAllByRole("columnheader").find((h) => h.dataset.col === "outcome");
    expect(outcome?.textContent).toBe("Outcome");
  });

  it("marks the winning truth with a check glyph in its column, and fills no cell", async () => {
    await openView();
    const reserved = row("192.0.2.5|ghost");
    const wins = within(reserved).getAllByTestId("reconcile-wins");
    expect(wins).toHaveLength(1);
    expect(wins[0]?.getAttribute("aria-label")).toBe("Wins");
    expect(wins[0]?.closest("td")?.dataset.col).toBe("intent");
    expect(within(row("192.0.2.44|conflict")).queryByTestId("reconcile-wins")).toBeNull();
    // No green tag, no winner class that the old view filled.
    expect(document.querySelector(".tag.ok, td.winner")).toBeNull();
    expect(cell(reserved, "outcome").textContent).toBe("Intent wins");
    expect(cell(row("192.0.2.20|ghost"), "outcome").textContent).toBe("Lease wins");
    expect(cell(row("192.0.2.44|conflict"), "outcome").textContent).toBe("No winner");
  });

  it("shows the four truths of a row on one line each", async () => {
    await openView();
    const conflict = row("192.0.2.44|conflict");
    expect(cell(conflict, "intent").textContent).toContain("speaker-den");
    expect(cell(conflict, "intent").textContent).toContain("reserved");
    expect(cell(conflict, "lease").textContent).toBe("00:00:5e:00:53:2c");
    expect(cell(conflict, "dns").textContent).toBe("speaker-den.example.test");
    expect(cell(conflict, "scan").textContent).toBe("00:00:5e:00:53:c8");
    expect(cell(row("192.0.2.5|ghost"), "lease").textContent).toBe("–");
    expect(within(row("192.0.2.5|ghost")).getByTestId("reconcile-host").getAttribute("href")).toBe("/ipam/hosts/ap-garage");
    expect(within(row("192.0.2.5|ghost")).getByRole("link", { name: "192.0.2.5" }).getAttribute("href")).toBe(`/ipam/addresses/192.0.2.5?vrf=${IPAM_IDS.vrf.default}`);
    expect(cell(row("192.0.2.90|ptr_mismatch"), "dns").textContent).toBe("media.example.test");
  });

  it("offers the OS field, the vendors and the rule as columns of the column menu", async () => {
    await openView();
    expect(cell(row("192.0.2.150|rogue"), "os")).toBeNull();
    fireEvent.click(screen.getByTestId("column-chooser"));
    const chooser = await screen.findByTestId("column-chooser-panel");
    for (const id of ["os", "vendors", "rule"]) fireEvent.click(chooser.querySelector(`li[data-col='${id}'] input`) as HTMLInputElement);
    await waitFor(() => expect(cell(row("192.0.2.150|rogue"), "os")).toBeTruthy());
    expect(within(row("192.0.2.150|rogue")).getByTestId("reconcile-os-guess").textContent).toBe("Windows 10 or 11 (or Server 2016 and later) (85 %)");
    expect(within(row("192.0.2.150|rogue")).getByTestId("reconcile-vendors").textContent).toContain("MSFT 5.0");
    expect(within(row("192.0.2.78|orphan")).getByTestId("reconcile-rule").textContent).toBe("Written by hand, so it stays as written.");
  });

  it("carries the default action of each row's finding", async () => {
    await openView();
    expect((await within(row("192.0.2.150|rogue")).findByTestId("finding-action")).textContent).toBe("Adopt");
    expect(within(row("192.0.2.30|ptr_mismatch")).getByTestId("finding-action").textContent).toBe("Fix PTR");
    expect(within(row("192.0.2.44|conflict")).getByTestId("finding-action").textContent).toBe("Resolve");
    expect(within(row("192.0.2.5|ghost")).queryByTestId("finding-action")).toBeNull();
  });

  it("is reachable from the IPAM navigation and has no accessibility violations", async () => {
    const { container } = await openView();
    const tab = within(screen.getByTestId("ipam-nav")).getByRole("link", { name: "Reconciliation" });
    expect(tab.getAttribute("href")).toBe("/ipam/reconcile");
    expect(tab.getAttribute("aria-current")).toBe("page");
    expect(await axeViolations(container)).toEqual([]);
  });
});

describe("the side panel", () => {
  it("opens the truths of a row without a proposal, with the conflict's MACs first, and keeps it in the URL", async () => {
    const { location } = await openView();
    fireEvent.click(cell(row("192.0.2.44|conflict"), "lease"));
    const panel = await screen.findByTestId("finding-panel");
    expect(location()).toContain("row=192.0.2.44");
    expect(within(panel).getAllByTestId("conflict-mac").map((m) => m.dataset.mac)).toEqual(["00:00:5e:00:53:2c", "00:00:5e:00:53:c8"]);
    expect(within(panel).getByTestId("truth-list").textContent).toContain("speaker-den.example.test");
    expect(within(panel).queryByTestId("finding-reconcile-link")).toBeNull();
    fireEvent.click(within(panel).getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByTestId("finding-panel")).toBeNull());
    expect(location()).not.toContain("row=");
  });

  it("opens the proposal of a row that has one, with its decisions", async () => {
    await openView();
    fireEvent.click(cell(row("192.0.2.150|rogue"), "scan"));
    const panel = await screen.findByTestId("proposal-panel");
    expect(panel.dataset.id).toBe(RECONCILE_IDS.proposal.mediaPc);
    expect(await within(panel).findByTestId("discovery-approve")).toBeTruthy();
  });
});

describe("the scope", () => {
  it("asks for every kind and the findings, with no filter at first", async () => {
    await openView();
    expect(requests.map((r) => r.kind).sort()).toEqual(["conflict", "ghost", "orphan", "ptr_mismatch", "rogue"]);
    for (const r of requests) {
      expect(r.prefix).toBeUndefined();
      expect(r.host).toBeUndefined();
    }
    expect(findingRequests.some((q) => q.get("prefix") === null)).toBe(true);
    expect(screen.getByTestId("reconcile-facts").textContent).toBe("All networks · 2 to act on · 5 to review · 3 info");
  });

  it("sends the prefix to every kind and to the findings, and names it in the facts", async () => {
    const { location } = await openView();
    await waitFor(() => expect(within(screen.getByTestId("filter-prefix")).getAllByRole("option").length).toBeGreaterThan(3));
    requests = [];
    findingRequests = [];
    fireEvent.change(screen.getByTestId("filter-prefix"), { target: { value: IPAM_IDS.prefix.iot } });
    await waitFor(() => expect(requests).toHaveLength(5));
    expect(new Set(requests.map((r) => r.prefix))).toEqual(new Set([IPAM_IDS.prefix.iot]));
    await waitFor(() => expect(findingRequests.some((q) => q.get("prefix") === IPAM_IDS.prefix.iot)).toBe(true));
    expect(location()).toContain(`prefix=${IPAM_IDS.prefix.iot}`);
    // The IoT network has no finding in the mock.
    expect(await screen.findByTestId("reconcile-empty")).toBeTruthy();
    expect(screen.getByTestId("reconcile-facts").textContent).toMatch(/^198\.51\.100\.0\/2\d · 0 to act on/);

    fireEvent.change(screen.getByTestId("filter-prefix"), { target: { value: IPAM_IDS.prefix.lan } });
    await waitFor(() => expect(dataRows()).toHaveLength(10));
  });

  it("finds a host by name, sends its id, shows it as a chip and removes it again", async () => {
    const { location } = await openView();
    requests = [];
    fireEvent.input(screen.getByTestId("filter-host-input"), { target: { value: "Speaker-Den" } });
    fireEvent.click(screen.getByTestId("filter-host-apply"));
    const speaker = HOST_IDS["speaker-den"] as string;
    await waitFor(() => expect(requests.length).toBeGreaterThanOrEqual(5));
    expect(new Set(requests.map((r) => r.host))).toEqual(new Set([speaker]));
    expect(location()).toContain(`host=${speaker}`);
    await waitFor(() => expect(dataRows().map((r) => r.dataset.id)).toEqual(["192.0.2.44|conflict"]));
    expect((await screen.findByTestId("filter-host")).textContent).toContain("Host speaker-den");
    fireEvent.click(within(screen.getByTestId("filter-host")).getByTestId("filter-chip-remove"));
    await waitFor(() => expect(dataRows()).toHaveLength(10));
    expect(screen.queryByTestId("filter-host")).toBeNull();
  });

  it("says so when no host has the name, and sends nothing", async () => {
    await openView();
    requests = [];
    fireEvent.input(screen.getByTestId("filter-host-input"), { target: { value: "no-such-host" } });
    fireEvent.click(screen.getByTestId("filter-host-apply"));
    expect((await screen.findByTestId("filter-host-unknown")).textContent).toBe("No host is named no-such-host.");
    expect(requests).toEqual([]);
  });

  it("narrows the page to one kind, and back to all", async () => {
    const { location } = await openView();
    requests = [];
    fireEvent.click(screen.getByTestId("filter-kind-ghost"));
    await waitFor(() => expect(groupKeys()).toEqual(["info:ghost"]));
    expect(location()).toContain("kind=ghost");
    // The ghosts stay as they were read; nothing is read again.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(requests).toEqual([]);
    expect(screen.getByTestId("filter-kind-ghost").getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(screen.getByTestId("filter-kind-all"));
    await waitFor(() => expect(dataRows()).toHaveLength(10));
    expect(location()).not.toContain("kind=");
  });

  it("starts from the filters of the URL", async () => {
    renderView(`/ipam/reconcile?kind=rogue&host=${HOST_IDS["speaker-den"]}`);
    await waitFor(() => expect(requests.length).toBeGreaterThan(0));
    expect(requests.every((r) => r.kind === "rogue" && r.host === HOST_IDS["speaker-den"])).toBe(true);
    expect(await screen.findByTestId("reconcile-empty")).toBeTruthy();
    expect((await screen.findByTestId("filter-host")).textContent).toContain("speaker-den");
  });
});

describe("paging and errors", () => {
  it("ends the group of a kind with more rows with 'Show more' and appends the next page", async () => {
    const ghosts = seed().filter((r) => r.kind === "ghost");
    server.use(
      http.get("/api/v1/ipam/reconcile", ({ request }) => {
        const url = new URL(request.url);
        const kind = url.searchParams.get("kind");
        const cursor = url.searchParams.get("cursor");
        const items = kind === "ghost" ? (cursor ? ghosts.slice(1) : ghosts.slice(0, 1)) : [];
        return HttpResponse.json({ items, next_cursor: kind === "ghost" && !cursor ? "page-2" : null, revision: 1 });
      }),
    );
    renderView("/ipam/reconcile?kind=ghost");
    await waitFor(() => expect(groupRows()).toHaveLength(1));
    expect(dataRows().map((r) => r.dataset.id)).toEqual(["192.0.2.5|ghost"]);
    expect(within(groupRows()[0] as HTMLElement).getByTestId("group-count").textContent).toBe("1+");
    requests = [];
    fireEvent.click(screen.getByTestId("reconcile-more"));
    await waitFor(() => expect(dataRows()).toHaveLength(2));
    expect(requests.map((r) => r.cursor)).toEqual(["page-2"]);
    expect(screen.queryByTestId("reconcile-more")).toBeNull();
    expect(within(groupRows()[0] as HTMLElement).getByTestId("group-count").textContent).toBe("2");
  });

  it("shows the error of one kind and reads it again on request, the others stay", async () => {
    let fail = true;
    server.use(
      http.get("/api/v1/ipam/reconcile", ({ request }) => {
        const url = new URL(request.url);
        const kind = url.searchParams.get("kind");
        if (kind === "orphan" && fail) {
          return HttpResponse.json(
            { type: "about:blank", title: "Unavailable", status: 503, code: "sys.unavailable", detail: "", params: {} },
            { status: 503, headers: { "content-type": "application/problem+json" } },
          );
        }
        return HttpResponse.json({ items: seed().filter((r) => r.kind === kind), next_cursor: null, revision: 1 });
      }),
    );
    renderView();
    await screen.findByTestId("reconcile-error-orphan");
    await waitFor(() => expect(dataRows()).toHaveLength(8));
    fail = false;
    fireEvent.click(within(screen.getByTestId("reconcile-error-orphan")).getByTestId("reconcile-retry"));
    await waitFor(() => expect(dataRows()).toHaveLength(10));
    expect(screen.queryByTestId("reconcile-error-orphan")).toBeNull();
  });
});

describe("the navigation", () => {
  it("lists the reconciliation view among the IPAM sections", () => {
    renderRoute(IpamNav, { url: "/ipam/addresses", path: "/ipam/addresses" });
    const tab = within(screen.getByTestId("ipam-nav")).getByRole("link", { name: "Reconciliation" });
    expect(tab.getAttribute("href")).toBe("/ipam/reconcile");
    expect(tab.getAttribute("aria-current")).toBeNull();
  });
});
