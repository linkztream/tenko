// The leases: the grid with the client, the name, the network of the scope and when a lease ends,
// the filters sent as query parameters, paging with the cursor, the release with its dialog (the body
// sent, the refusal of the server shown, who sees it), the live view with its sampling, the status
// strip of the role (and a node that does not run it), the states without a service, Swedish.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { events, type ApiEvent } from "../../api/events";
import { db } from "../../api/mock/db";
import { server } from "../../api/mock/node";
import { dhcpLeaseState, docMac, grantMockLease } from "../../api/mock/routes-dhcp-leases";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { cell, dhcpNotBuilt, dhcpSwitchedOff, recordWrites, row, rowAction, rowActions, rows } from "../testkit";
import LeasesPage from "./LeasesPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  vi.restoreAllMocks();
  setSessionForTest(null);
  await setLocale("en");
});

const GRID = "dhcp-leases";
const LAN = "192.0.2.0/24";
const open = (url = "/dhcp/leases") => renderRoute(LeasesPage, { url, path: "/dhcp/leases" });
const loaded = () => waitFor(() => expect(rows(GRID).length).toBeGreaterThan(0));

/** The URLs of the reads of the lease list so far. */
function leaseReads(spy: { mock: { calls: unknown[][] } }): URL[] {
  return spy.mock.calls.map(([url]) => new URL(String(url), "http://localhost")).filter((url) => url.pathname === "/api/v1/dhcp/leases");
}

function problem(status: number, code: string): Response {
  return HttpResponse.json({ type: "about:blank", status, code, title: "Problem", detail: code, params: {} }, { status, headers: { "content-type": "application/problem+json" } });
}

describe("the leases", () => {
  it("lists every lease with its state, client, name, network, end and relay", async () => {
    const view = open();
    await loaded();
    const first = row(GRID, "192.0.2.100");
    expect(within(first).getByTestId("lease-state").dataset.key).toBe("active");
    expect(cell(first, "mac").textContent).toBe("00:00:5e:00:53:10");
    expect(cell(first, "name").textContent).toContain("host-1.example.test");
    expect(cell(first, "name").textContent).toContain("(host-1)");
    expect(cell(first, "relay").textContent).toBe("192.0.2.1");
    expect(within(first).getByTestId("lease-ends").querySelector("time")?.getAttribute("datetime")).toBe(dhcpLeaseState().leases[0]?.ends);
    await waitFor(() => expect(cell(first, "scope").textContent).toBe(LAN));
    expect(within(row(GRID, "192.0.2.102")).getByTestId("lease-reserved")).toBeTruthy();
    expect(within(row(GRID, "192.0.2.109")).getByTestId("lease-state").dataset.key).toBe("expired");
    expect(within(row(GRID, "192.0.2.111")).getByTestId("lease-state").dataset.key).toBe("abandoned");
    expect(rows(GRID).map((r) => r.dataset.key)).toEqual(Array.from({ length: 12 }, (_, i) => `192.0.2.${100 + i}`));
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("links an address to its history", async () => {
    open();
    await loaded();
    expect(within(row(GRID, "192.0.2.101")).getByTestId("lease-history-link").getAttribute("href")).toBe("/dhcp/history?addr=192.0.2.101");
  });

  it("sends the filters as query parameters", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    open();
    await loaded();
    const last = () => leaseReads(spy).at(-1)!.searchParams;

    fireEvent.change(screen.getByTestId("filter-addr"), { target: { value: "192.0.2.10" } });
    await waitFor(() => expect(last().get("addr")).toBe("192.0.2.10"));
    await waitFor(() => expect(rows(GRID)).toHaveLength(10));

    fireEvent.change(screen.getByTestId("filter-mac"), { target: { value: "00-00-5E-00-53-12" } });
    await waitFor(() => expect(last().get("mac")).toBe("00:00:5e:00:53:12"));
    await waitFor(() => expect(rows(GRID).map((r) => r.dataset.key)).toEqual(["192.0.2.102"]));

    fireEvent.change(screen.getByTestId("filter-mac"), { target: { value: "" } });
    fireEvent.change(screen.getByTestId("filter-addr"), { target: { value: "" } });
    fireEvent.change(screen.getByTestId("filter-name"), { target: { value: "HOST-3" } });
    await waitFor(() => expect(last().get("name")).toBe("HOST-3"));
    await waitFor(() => expect(rows(GRID).map((r) => r.dataset.key)).toEqual(["192.0.2.102"]));
    expect(last().get("addr")).toBeNull();
    expect(last().get("mac")).toBeNull();

    fireEvent.change(screen.getByTestId("filter-name"), { target: { value: "" } });
    fireEvent.change(screen.getByTestId("filter-state"), { target: { value: "expired" } });
    await waitFor(() => expect(last().get("state")).toBe("expired"));
    await waitFor(() => expect(rows(GRID).map((r) => r.dataset.key)).toEqual(["192.0.2.109"]));

    fireEvent.change(screen.getByTestId("filter-state"), { target: { value: "" } });
    await waitFor(() => expect(last().get("state")).toBeNull());
    const scope = dhcpLeaseState().leases[0]!.scope;
    fireEvent.change(screen.getByTestId("filter-scope"), { target: { value: scope } });
    await waitFor(() => expect(last().get("scope")).toBe(scope));

    fireEvent.click(screen.getByTestId("leases-reset"));
    await waitFor(() => expect([...last().keys()].filter((k) => ["scope", "addr", "mac", "name", "state"].includes(k))).toEqual([]));
    expect(screen.queryByTestId("leases-reset")).toBeNull();
  });

  it("takes the filters from the link and says when nothing matches", async () => {
    open("/dhcp/leases?name=nobody");
    expect(await screen.findByTestId("dhcp-leases-empty")).toBeTruthy();
    expect(screen.getByTestId("dhcp-leases-empty").dataset.filtered).toBe("true");
    expect((screen.getByTestId("filter-name") as HTMLInputElement).value).toBe("nobody");
  });

  it("points at a MAC address that is none and shows what the server answers", async () => {
    open("/dhcp/leases?mac=nonsense");
    expect((await screen.findByTestId("field-error")).dataset.field).toBe("mac");
    expect(await screen.findByTestId("error-notice")).toBeTruthy();
  });

  it("reads the next page with the cursor", async () => {
    for (let i = 0; i < 100; i += 1) grantMockLease({ mac: docMac(0x40 + (i % 100)), hostname: `bulk-${i}` });
    const spy = vi.spyOn(globalThis, "fetch");
    open();
    await loaded();
    const more = await screen.findByTestId("leases-more");
    expect(leaseReads(spy).at(-1)!.searchParams.get("limit")).toBe("100");
    expect(leaseReads(spy).at(-1)!.searchParams.get("cursor")).toBeNull();
    fireEvent.click(more);
    await waitFor(() => expect(leaseReads(spy).some((url) => url.searchParams.get("cursor") !== null)).toBe(true));
    await waitFor(() => expect(screen.queryByTestId("leases-more")).toBeNull());
  });

  describe("release", () => {
    it("asks for confirmation with a reason, sends the VRF and the reason, and shows the new state", async () => {
      const writes = recordWrites();
      open();
      await loaded();
      await rowAction(row(GRID, "192.0.2.100"), "release");
      const dialog = await screen.findByTestId("dialog-lease-release");
      expect(dialog.textContent).toContain("192.0.2.100");
      expect(dialog.textContent).toContain("00:00:5e:00:53:10");
      fireEvent.input(within(dialog).getByTestId("field-reason"), { target: { value: "Printer moved" } });
      fireEvent.click(within(dialog).getByTestId("confirm-ok"));
      await waitFor(() => expect(within(row(GRID, "192.0.2.100")).getByTestId("lease-state").dataset.key).toBe("released"));
      expect(screen.queryByTestId("dialog-lease-release")).toBeNull();
      const sent = writes().find((w) => w.method === "POST");
      expect(sent?.url).toContain("/api/v1/dhcp/leases/192.0.2.100/release");
      expect(sent?.body).toEqual({ vrf: dhcpLeaseState().leases[0]!.vrf, reason: "Printer moved" });
      expect(await screen.findByText("Released 192.0.2.100")).toBeTruthy();
    });

    it("sends no reason when none is typed", async () => {
      const writes = recordWrites();
      open();
      await loaded();
      await rowAction(row(GRID, "192.0.2.101"), "release");
      fireEvent.click(within(await screen.findByTestId("dialog-lease-release")).getByTestId("confirm-ok"));
      await waitFor(() => expect(within(row(GRID, "192.0.2.101")).getByTestId("lease-state").dataset.key).toBe("released"));
      expect(writes().find((w) => w.method === "POST")?.body).toEqual({ vrf: dhcpLeaseState().leases[1]!.vrf });
    });

    it("keeps the dialog open with the refusal of the server and reads the list again", async () => {
      open();
      await loaded();
      // Another operator released it meanwhile: the page still shows it as active.
      dhcpLeaseState().leases[3]!.state = "released";
      await rowAction(row(GRID, "192.0.2.103"), "release");
      const dialog = await screen.findByTestId("dialog-lease-release");
      fireEvent.click(within(dialog).getByTestId("confirm-ok"));
      const refusal = await within(dialog).findByTestId("error-notice");
      expect(refusal.dataset.code).toBe("dhcp.lease.state");
      expect(refusal.textContent).toBe("The state of the lease does not allow this.");
      await waitFor(() => expect(within(row(GRID, "192.0.2.103")).getByTestId("lease-state").dataset.key).toBe("released"));
      fireEvent.click(within(dialog).getByTestId("confirm-cancel"));
      await waitFor(() => expect(screen.queryByTestId("dialog-lease-release")).toBeNull());
    });

    it("cannot release a lease that is not active", async () => {
      open();
      await loaded();
      fireEvent.click(within(row(GRID, "192.0.2.109")).getByRole("button", { name: /^Actions for/ }));
      const menu = await screen.findByTestId("row-menu");
      const item = within(menu)
        .getAllByTestId("menu-item")
        .find((i) => i.dataset.key === "release");
      expect(item?.getAttribute("aria-disabled")).toBe("true");
    });

    it("offers a viewer no release", async () => {
      await signInWithRoles(["viewer"]);
      open();
      await loaded();
      expect(await rowActions(row(GRID, "192.0.2.100"))).toEqual(["history"]);
    });
  });

  describe("the live view", () => {
    /** The handler the page registered for the `dhcp` topic, to feed it events as the stream would. */
    function stream(): { feed: (n: number, tables?: string[]) => void } {
      const subscribe = vi.spyOn(events, "subscribe");
      return {
        feed: (n, tables = ["dhcp.leases"]) => {
          const handler = subscribe.mock.calls.find(([topic]) => topic === "dhcp")?.[1];
          if (!handler) throw new Error("the page did not subscribe to the dhcp topic");
          const event: ApiEvent = { topic: "dhcp", type: "dhcp", objects: [], deleted: [], revision: db.revision + 100_000 + n, data: { tables, revision: db.revision + 100_000 + n } };
          handler(event);
        },
      };
    }

    it("shows a lease that appears without a reload", async () => {
      const { feed } = stream();
      open();
      await loaded();
      grantMockLease({ mac: docMac(0x41), hostname: "client-new" });
      feed(1);
      await waitFor(() => expect(row(GRID, "192.0.2.112")).toBeTruthy());
      expect(cell(row(GRID, "192.0.2.112"), "name").textContent).toBe("client-new");
    });

    it("reads once for a burst of a thousand events and says how many changes it folded", async () => {
      const { feed } = stream();
      const spy = vi.spyOn(globalThis, "fetch");
      open();
      await loaded();
      const before = leaseReads(spy).length;
      for (let i = 0; i < 1000; i += 1) feed(i);
      await waitFor(() => expect(leaseReads(spy).length).toBe(before + 1));
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(leaseReads(spy).length).toBe(before + 1);
      const folded = screen.getByTestId("leases-folded");
      expect(folded.dataset.count).toBe("950");
      expect(folded.textContent).toContain("950");
      // A second without events forgets them.
      await waitFor(() => expect(screen.getByTestId("leases-folded").dataset.count).toBe("0"), { timeout: 2500 });
      expect(screen.getByTestId("leases-folded").textContent).toBe("");
    });

    it("ignores events of other tables", async () => {
      const { feed } = stream();
      const spy = vi.spyOn(globalThis, "fetch");
      open();
      await loaded();
      const before = leaseReads(spy).length;
      feed(1, ["dhcp.config"]);
      feed(2, ["dhcp.scopes"]);
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(leaseReads(spy).length).toBe(before);
    });

    it("pauses with the toggle and reads once when it is switched on again", async () => {
      const { feed } = stream();
      const spy = vi.spyOn(globalThis, "fetch");
      open();
      await loaded();
      const toggle = screen.getByTestId("leases-live") as HTMLInputElement;
      expect(toggle.checked).toBe(true);
      fireEvent.click(toggle);
      expect(toggle.checked).toBe(false);
      grantMockLease({ mac: docMac(0x42), hostname: "client-paused" });
      const before = leaseReads(spy).length;
      feed(1);
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(leaseReads(spy).length).toBe(before);
      expect(rows(GRID).some((r) => r.dataset.key === "192.0.2.112")).toBe(false);
      fireEvent.click(toggle);
      await waitFor(() => expect(row(GRID, "192.0.2.112")).toBeTruthy());
      expect(leaseReads(spy).length).toBe(before + 1);
    });
  });

  describe("the status strip", () => {
    it("shows what the role does", async () => {
      open();
      const strip = await screen.findByTestId("dhcp-strip");
      expect(within(strip).getByTestId("strip-serving").textContent).toBe("Serving");
      expect(within(strip).getByTestId("strip-accepting").textContent).toBe("Accepting lease writes");
      expect(within(strip).getByTestId("strip-probe").textContent).toBe("Conflict detection on");
      expect(within(strip).getByTestId("strip-listeners").textContent).toBe("1 listener");
      expect(within(strip).getByTestId("strip-scopes").textContent).toBe("1 scope");
      const counts = Object.fromEntries(within(strip).getAllByTestId("strip-leases").map((el) => [el.dataset.key, el.textContent]));
      expect(counts.active).toContain("9");
      expect(counts.expired).toContain("1");
      expect(within(strip).getByTestId("strip-commit").textContent).toBe("Last commit 1.4 ms");
      expect(within(strip).getByTestId("strip-revision").textContent).toContain("Revision");
    });

    it("says that the node does not run the DHCP role", async () => {
      server.use(http.get("/api/v1/nodes/:id/dhcp", () => problem(409, "dhcp.node.not_dhcp")));
      open();
      expect(await screen.findByTestId("dhcp-strip-not-dhcp")).toBeTruthy();
      expect(screen.queryByTestId("dhcp-strip")).toBeNull();
      await loaded();
    });

    it("hides the strip when the node is unknown, and the list still works", async () => {
      server.use(http.get("/api/v1/nodes/:id/dhcp", () => problem(404, "cluster.node.not_found")));
      const spy = vi.spyOn(globalThis, "fetch");
      open();
      await loaded();
      await waitFor(() => expect(spy.mock.calls.some(([url]) => String(url).includes("/api/v1/nodes/1/dhcp"))).toBe(true));
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(screen.queryByTestId("dhcp-strip")).toBeNull();
      expect(screen.queryByTestId("dhcp-strip-not-dhcp")).toBeNull();
      expect(rows(GRID).length).toBeGreaterThan(0);
    });
  });

  it("says the module is switched off", async () => {
    dhcpSwitchedOff();
    open();
    expect(await screen.findByTestId("dhcp-off")).toBeTruthy();
  });

  it("says the service is not built", async () => {
    dhcpNotBuilt();
    open();
    expect(await screen.findByTestId("dhcp-not-built")).toBeTruthy();
  });

  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await loaded();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("Lån");
    expect(within(row(GRID, "192.0.2.100")).getByTestId("lease-state").textContent).toBe("Aktivt");
    expect(within(row(GRID, "192.0.2.109")).getByTestId("lease-state").textContent).toBe("Utgånget");
    expect(screen.getByLabelText("Adressen börjar med")).toBeTruthy();
    expect((await screen.findByTestId("strip-serving")).textContent).toBe("Svarar");
  });
});
