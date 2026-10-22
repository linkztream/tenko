import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { HOST_IDS, IPAM_IDS } from "../../api/mock/ipam/api";
import { server } from "../../api/mock/node";
import { RECONCILE_IDS } from "../../api/mock/reconcile-store";
import { seedRows } from "../../api/mock/ipam-reconcile-model";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { IpamNav } from "../IpamNav";
import ReconcileView from "./ReconcileView";

let requests: Record<string, string>[] = [];

beforeEach(async () => {
  requests = [];
  server.events.on("request:start", ({ request }) => {
    const url = new URL(request.url);
    if (url.pathname === "/api/v1/ipam/reconcile") requests.push(Object.fromEntries(url.searchParams));
  });
  await signInAlex();
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

const section = (kind: string) => screen.getByTestId(`reconcile-section-${kind}`);
const rowsOf = (kind: string) => within(section(kind)).queryAllByTestId("reconcile-row");
const row = (key: string): HTMLElement => {
  const found = screen.getAllByTestId("reconcile-row").find((r) => r.dataset.key === key);
  if (!found) throw new Error(`no row ${key}`);
  return found;
};

/** Renders the view and waits until every list has answered. */
async function openView(url?: string) {
  const view = renderView(url);
  await waitFor(() => {
    for (const el of document.querySelectorAll("[data-testid^='reconcile-section-']")) {
      expect((el as HTMLElement).dataset.count).toBeDefined();
    }
  });
  return view;
}

describe("the lists", () => {
  it("shows one list per kind with its count, the rule in words and who wins", async () => {
    await openView();
    const kinds = [...document.querySelectorAll("[data-testid^='reconcile-section-']")].map((el) => (el as HTMLElement).dataset.kind);
    expect(kinds).toEqual(["conflict", "ghost", "rogue", "orphan", "ptr_mismatch"]);
    expect(screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent)).toEqual([
      "Conflicts2",
      "Ghost addresses2",
      "Unknown devices2",
      "Orphaned records2",
      "PTR mismatches2",
    ]);

    // Intent wins for the reserved host, and the rule is said in words (not the server's text).
    const reserved = row("192.0.2.5|ghost");
    expect(reserved.dataset.winner).toBe("intent");
    expect(within(reserved).getByTestId("reconcile-winner").textContent).toBe("Intent wins");
    expect(within(reserved).getByTestId("reconcile-rule").textContent).toBe("Intent wins: the host is managed, so what intent says stands.");
    expect(reserved.textContent).not.toContain("intent wins for a managed host");

    // The lease wins for the dynamic host.
    const dynamic = row("192.0.2.20|ghost");
    expect(within(dynamic).getByTestId("reconcile-winner").textContent).toBe("Lease wins");
    expect(within(dynamic).getByTestId("reconcile-rule").textContent).toContain("The lease wins: the host is dynamic");

    // A conflict has no winner and is never resolved automatically.
    const conflict = row("192.0.2.44|conflict");
    expect(conflict.dataset.winner).toBe("none");
    expect(within(conflict).getByTestId("reconcile-winner").textContent).toBe("No winner");
    expect(within(conflict).getByTestId("reconcile-rule").textContent).toContain("Never resolved automatically");
    expect(within(conflict).queryByTestId("reconcile-wins")).toBeNull();

    // The records of an orphan: IPAM wrote the first, a person wrote the second.
    expect(within(row("192.0.2.77|orphan")).getByTestId("reconcile-rule").textContent).toContain("the orphan rule removes it");
    expect(within(row("192.0.2.78|orphan")).getByTestId("reconcile-rule").textContent).toBe("Written by hand, so it stays as written.");
    expect(within(row("192.0.2.78|orphan")).getByTestId("reconcile-winner").textContent).toBe("DNS wins");

    // A PTR mismatch: intent wins for a managed host, the forward record where intent says nothing.
    expect(within(row("192.0.2.30|ptr_mismatch")).getByTestId("reconcile-rule").textContent).toContain("Intent wins");
    expect(within(row("192.0.2.90|ptr_mismatch")).getByTestId("reconcile-rule").textContent).toBe("The forward record wins: the PTR record should follow it.");

    // The newest sighting wins without intent.
    expect(within(row("192.0.2.151|rogue")).getByTestId("reconcile-winner").textContent).toBe("Scan wins");
    expect(within(row("192.0.2.151|rogue")).getByTestId("reconcile-rule").textContent).toContain("newest sighting wins");
  });

  it("shows the four truths of a row and marks the winner by a tag and an attribute", async () => {
    await openView();
    const conflict = row("192.0.2.44|conflict");
    const cell = (truth: string) => conflict.querySelector(`td[data-truth='${truth}']`) as HTMLElement;
    expect(cell("intent").textContent).toContain("speaker-den");
    expect(cell("intent").textContent).toContain("reserved");
    expect(cell("lease").textContent).toContain("00:00:5e:00:53:2c");
    expect(cell("lease").textContent).toContain("dhcp:1");
    expect(cell("dns").textContent).toContain("speaker-den.example.test");
    expect(cell("scan").textContent).toContain("00:00:5e:00:53:c8");
    expect(cell("scan").textContent).toContain("probe:2:arp");

    const reserved = row("192.0.2.5|ghost");
    const winning = reserved.querySelectorAll("td[data-winner='true']");
    expect(winning).toHaveLength(1);
    expect((winning[0] as HTMLElement).dataset.truth).toBe("intent");
    expect(within(winning[0] as HTMLElement).getByTestId("reconcile-wins").textContent).toBe("Wins");

    // A truth that has nothing to say is a dash.
    expect((reserved.querySelector("td[data-truth='lease']") as HTMLElement).textContent).toBe("–");
    const orphan = row("192.0.2.77|orphan");
    expect(within(orphan).getByTestId("reconcile-forward").textContent).toBe("old-nas.example.test");
    expect(within(orphan).getByTestId("reconcile-ptr").textContent).toBe("old-nas.example.test");
  });

  it("shows the OS field and the vendors of a row", async () => {
    await openView();
    const rogue = row("192.0.2.150|rogue");
    expect(within(rogue).getByTestId("reconcile-os-guess").textContent).toBe("Windows 10 or 11 (or Server 2016 and later) (85 %)");
    expect(within(rogue).getByTestId("reconcile-os-source").textContent).toBe("from dhcp:1 (Lease)");
    expect(within(rogue).getByTestId("reconcile-vendors").textContent).toContain("MSFT 5.0");
    expect(within(row("192.0.2.151|rogue")).queryByTestId("reconcile-os")).toBeNull();
  });

  it("links the discovered-host proposal of a rogue, and only where there is one", async () => {
    await openView();
    const link = within(row("192.0.2.150|rogue")).getByTestId("reconcile-proposal");
    expect(link.getAttribute("href")).toBe(`/discovery/${RECONCILE_IDS.proposal.mediaPc}`);
    expect(link.textContent).toBe("Open the proposal");
    expect(within(row("192.0.2.151|rogue")).queryByTestId("reconcile-proposal")).toBeNull();
    expect(screen.getAllByTestId("reconcile-proposal")).toHaveLength(1);
    fireEvent.click(link);
    await screen.findByTestId("proposal-route");
  });

  it("links the address and the host of a row", async () => {
    await openView();
    const reserved = row("192.0.2.5|ghost");
    expect(within(reserved).getByRole("link", { name: "192.0.2.5" }).getAttribute("href")).toBe(`/ipam/addresses/192.0.2.5?vrf=${IPAM_IDS.vrf.default}`);
    expect(within(reserved).getByTestId("reconcile-host").getAttribute("href")).toBe("/ipam/hosts/ap-garage");
  });

  it("is reachable from the IPAM navigation and has no accessibility violations", async () => {
    const { container } = await openView();
    const tab = within(screen.getByTestId("ipam-nav")).getByRole("link", { name: "Reconciliation" });
    expect(tab.getAttribute("href")).toBe("/ipam/reconcile");
    expect(tab.getAttribute("aria-current")).toBe("page");
    expect(await axeViolations(container)).toEqual([]);
  });
});

describe("the filters", () => {
  it("asks for one list per kind, with no filter at first", async () => {
    await openView();
    expect(requests.map((r) => r.kind).sort()).toEqual(["conflict", "ghost", "orphan", "ptr_mismatch", "rogue"]);
    for (const r of requests) {
      expect(r.prefix).toBeUndefined();
      expect(r.host).toBeUndefined();
      expect(r.limit).toBe("50");
    }
  });

  it("narrows the page to one kind, and back to all", async () => {
    const { location } = await openView();
    requests = [];
    fireEvent.click(screen.getByTestId("filter-kind-ghost"));
    await waitFor(() => expect(document.querySelectorAll("[data-testid^='reconcile-section-']")).toHaveLength(1));
    expect(section("ghost")).toBeTruthy();
    expect(location()).toContain("kind=ghost");
    expect(screen.getByTestId("filter-kind-ghost").getAttribute("aria-pressed")).toBe("true");
    await waitFor(() => expect(rowsOf("ghost")).toHaveLength(2));
    // The list of the kind was read again for the new view only (the ghost list stays as it is).
    expect(requests.every((r) => r.kind === "ghost")).toBe(true);

    fireEvent.click(screen.getByTestId("filter-kind-all"));
    await waitFor(() => expect(document.querySelectorAll("[data-testid^='reconcile-section-']")).toHaveLength(5));
    expect(location()).not.toContain("kind=");
  });

  it("sends the prefix to every list and shows what is left", async () => {
    const { location } = await openView();
    await waitFor(() => expect(within(screen.getByTestId("filter-prefix")).getAllByRole("option").length).toBeGreaterThan(3));
    requests = [];
    fireEvent.change(screen.getByTestId("filter-prefix"), { target: { value: IPAM_IDS.prefix.iot } });
    await waitFor(() => expect(requests).toHaveLength(5));
    expect(new Set(requests.map((r) => r.prefix))).toEqual(new Set([IPAM_IDS.prefix.iot]));
    expect(location()).toContain(`prefix=${IPAM_IDS.prefix.iot}`);
    // The IoT network has no finding in the mock.
    await waitFor(() => expect(screen.getAllByTestId("reconcile-empty")).toHaveLength(5));
    expect(screen.queryAllByTestId("reconcile-row")).toHaveLength(0);

    fireEvent.change(screen.getByTestId("filter-prefix"), { target: { value: IPAM_IDS.prefix.lan } });
    await waitFor(() => expect(screen.getAllByTestId("reconcile-row")).toHaveLength(10));
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
    await waitFor(() => expect(screen.getAllByTestId("reconcile-row").map((r) => r.dataset.key)).toEqual(["192.0.2.44|conflict"]));
    expect((await screen.findByTestId("filter-host")).textContent).toContain("Host speaker-den");

    requests = [];
    fireEvent.click(within(screen.getByTestId("filter-host")).getByTestId("filter-chip-remove"));
    await waitFor(() => expect(screen.getAllByTestId("reconcile-row")).toHaveLength(10));
    expect(requests.every((r) => r.host === undefined)).toBe(true);
    expect(screen.queryByTestId("filter-host")).toBeNull();
  });

  it("starts from the filters of the URL", async () => {
    await openView(`/ipam/reconcile?kind=rogue&host=${HOST_IDS["speaker-den"]}`);
    expect(document.querySelectorAll("[data-testid^='reconcile-section-']")).toHaveLength(1);
    expect(requests.every((r) => r.kind === "rogue" && r.host === HOST_IDS["speaker-den"])).toBe(true);
    await waitFor(() => expect(within(section("rogue")).getByTestId("reconcile-empty")).toBeTruthy());
    expect((await screen.findByTestId("filter-host")).textContent).toContain("speaker-den");
  });

  it("says so when no host has the name, and sends nothing", async () => {
    await openView();
    requests = [];
    fireEvent.input(screen.getByTestId("filter-host-input"), { target: { value: "no-such-host" } });
    fireEvent.click(screen.getByTestId("filter-host-apply"));
    expect((await screen.findByTestId("filter-host-unknown")).textContent).toBe("No host is named no-such-host.");
    expect(requests).toEqual([]);
    expect(screen.getAllByTestId("reconcile-row")).toHaveLength(10);
  });
});

describe("paging and errors", () => {
  const all = () => seedRows({ vrf: IPAM_IDS.vrf.default, prefix: IPAM_IDS.prefix.lan, host: (n) => HOST_IDS[n] ?? n, proposal: RECONCILE_IDS.proposal.mediaPc });

  it("appends the next page with 'Show more' and drops the button on the last page", async () => {
    const ghosts = all().filter((r) => r.kind === "ghost");
    server.use(
      http.get("/api/v1/ipam/reconcile", ({ request }) => {
        const url = new URL(request.url);
        const kind = url.searchParams.get("kind");
        const cursor = url.searchParams.get("cursor");
        const items = kind === "ghost" ? (cursor ? ghosts.slice(1) : ghosts.slice(0, 1)) : [];
        return HttpResponse.json({ items, next_cursor: kind === "ghost" && !cursor ? "page-2" : null, revision: 1 });
      }),
    );
    await openView("/ipam/reconcile?kind=ghost");
    expect(rowsOf("ghost")).toHaveLength(1);
    expect(within(section("ghost")).getByTestId("reconcile-count").textContent).toBe("1+");
    requests = [];
    fireEvent.click(within(section("ghost")).getByTestId("reconcile-more"));
    await waitFor(() => expect(rowsOf("ghost")).toHaveLength(2));
    expect(requests.map((r) => r.cursor)).toEqual(["page-2"]);
    expect(rowsOf("ghost").map((r) => r.dataset.key)).toEqual(["192.0.2.5|ghost", "192.0.2.20|ghost"]);
    expect(within(section("ghost")).queryByTestId("reconcile-more")).toBeNull();
    expect(within(section("ghost")).getByTestId("reconcile-count").textContent).toBe("2");
  });

  it("shows the error of one list and reads it again on request, the others stay", async () => {
    let fail = true;
    server.use(
      http.get("/api/v1/ipam/reconcile", ({ request }) => {
        const url = new URL(request.url);
        if (url.searchParams.get("kind") === "orphan" && fail) {
          return HttpResponse.json(
            { type: "about:blank", title: "Unavailable", status: 503, code: "sys.unavailable", detail: "", params: {} },
            { status: 503, headers: { "content-type": "application/problem+json" } },
          );
        }
        const kind = url.searchParams.get("kind");
        return HttpResponse.json({ items: all().filter((r) => r.kind === kind), next_cursor: null, revision: 1 });
      }),
    );
    renderView();
    await within(await screen.findByTestId("reconcile-section-orphan")).findByTestId("error-notice");
    await waitFor(() => expect(rowsOf("ghost")).toHaveLength(2));
    expect(rowsOf("orphan")).toHaveLength(0);
    fail = false;
    fireEvent.click(within(section("orphan")).getByTestId("reconcile-retry"));
    await waitFor(() => expect(rowsOf("orphan")).toHaveLength(2));
    expect(within(section("orphan")).queryByTestId("error-notice")).toBeNull();
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
