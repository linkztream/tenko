// The leases: the grid with the client, the name, the network of the scope and when a lease ends,
// the filters sent as query parameters, paging with the cursor, the release with its dialog (the body
// sent, the refusal of the server shown, who sees it), the live view with its sampling, the status
// strip of the role (and a node that does not run it), the live strip (the scope, the utilization
// bars and the count of the leases granted since the page was opened), the states without a
// service, Swedish.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { events, type ApiEvent } from "../../api/events";
import { db } from "../../api/mock/db";
import { DHCP_IDS } from "../../api/mock/dhcp-model";
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
    // The twelve DHCPv4 leases by address, then the four DHCPv6 leases (WP9.4) and the delegated prefix (WP9.2).
    expect(rows(GRID).map((r) => r.dataset.key)).toEqual([...Array.from({ length: 12 }, (_, i) => `192.0.2.${100 + i}`), ...[0, 1, 2, 3].map((n) => `2001:db8:0:10::10${n}`), "2001:db8:1:110::"]);
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
    await waitFor(() => expect(rows(GRID).map((r) => r.dataset.key)).toEqual(["192.0.2.109", "2001:db8:0:10::103"]));

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
      // The node serves both families (WP9.4): 1 DHCPv4 listener, none for DHCPv6; one scope of each.
      expect(within(strip).getByTestId("strip-listeners").textContent).toBe("1 DHCPv4 and 0 DHCPv6 listeners");
      expect(within(strip).getByTestId("strip-scopes").textContent).toBe("1 DHCPv4 and 1 DHCPv6 scopes");
      const counts = Object.fromEntries(within(strip).getAllByTestId("strip-leases").map((el) => [el.dataset.key, el.textContent]));
      expect(counts.active).toBe("9 DHCPv4 and 4 DHCPv6 active leases");
      expect(counts.expired).toContain("2");
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

  describe("the live strip", () => {
    const LAN_ID = DHCP_IDS.lan;
    const IOT_ID = DHCP_IDS.iot;

    /** The reads of `path` so far, as URLs. */
    function reads(spy: { mock: { calls: unknown[][] } }, match: (url: URL) => boolean): URL[] {
      return spy.mock.calls.map(([url]) => new URL(String(url), "http://localhost")).filter(match);
    }
    const utilReads = (spy: { mock: { calls: unknown[][] } }) => reads(spy, (url) => url.pathname.endsWith("/utilization"));
    const grantReads = (spy: { mock: { calls: unknown[][] } }) => reads(spy, (url) => url.pathname === "/api/v1/dhcp/history" && url.searchParams.get("kind") === "granted");
    const count = () => screen.getByTestId("leases-new").dataset.count;
    const text = () => screen.getByTestId("leases-new").textContent;
    const ready = () => waitFor(() => expect(screen.getByTestId("leases-new").textContent).not.toBe("…"));

    /** Eight scopes in the documentation range, the second, fourth and eighth fullest. */
    const used = [10, 80, 30, 95, 50, 20, 60, 70];
    function manyScopes(): void {
      const scopes = used.map((_, i) => ({ prefix: `0190d1c2-0000-7000-8000-00000000f50${i}`, cidr: `192.0.2.${i * 32}/27`, pools: 1, leases: 0, enabled: true, revision: 1 }));
      server.use(
        http.get("/api/v1/dhcp/scopes", () => HttpResponse.json({ items: scopes, next_cursor: null, revision: 1 })),
        http.get("/api/v1/dhcp/scopes/:prefix/utilization", ({ params }) => {
          const i = scopes.findIndex((s) => s.prefix === params.prefix);
          const leased = used[i] ?? 0;
          return HttpResponse.json({ prefix: params.prefix, pool_size: 100, leased, reserved: 0, abandoned: 0, free: 100 - leased, utilization: leased / 100, at: new Date().toISOString() });
        }),
      );
    }

    /** A grant of another scope at once, which the mock has no client for. */
    function grantElsewhere(n: number, scope = IOT_ID): void {
      const template = dhcpLeaseState().events[0]!;
      const at = new Date(Date.now() + 1000).toISOString();
      for (let i = 0; i < n; i += 1) dhcpLeaseState().events.push({ ...template, addr: `198.51.100.${(i % 200) + 10}`, at, kind: "granted", scope });
    }

    describe("the scope", () => {
      it("names no scope and offers a bar for each scope that sets the filter", async () => {
        open();
        await loaded();
        const strip = screen.getByTestId("leases-live-strip");
        expect(strip.dataset.scope).toBe("");
        expect(within(strip).getByTestId("leases-scope-name").textContent).toBe("All scopes");
        expect(within(strip).queryByTestId("leases-scope-link")).toBeNull();
        expect(within(strip).queryByTestId("leases-utilization")).toBeNull();
        // One bar for the DHCPv4 scope, one for the DHCPv6 scope (WP9.4) and one for the DHCPv6 scope with a delegation pool (WP9.2).
        await waitFor(() => expect(within(strip).getAllByTestId("leases-scope-bar")).toHaveLength(3));
        const bar = within(strip).getAllByTestId("leases-scope-bar").find((b) => b.dataset.key === LAN)!;
        // 12 of the 90 addresses of the pool.
        expect((await within(bar).findByTestId("scope-util")).dataset.key).toBe("13");
        expect(within(strip).queryByTestId("leases-scope-more")).toBeNull();

        fireEvent.click(bar);
        await waitFor(() => expect(screen.getByTestId("leases-live-strip").dataset.scope).toBe(LAN_ID));
        expect((screen.getByTestId("filter-scope") as HTMLSelectElement).value).toBe(LAN_ID);
        expect(screen.queryByTestId("leases-scope-bars")).toBeNull();
        expect(screen.getByTestId("leases-scope-name").textContent).toBe(LAN);
        expect(screen.getByTestId("leases-scope-link").getAttribute("href")).toBe(`/dhcp/scopes/${LAN_ID}`);
      });

      it("shows the bar of the chosen scope with its figures and the time it was read", async () => {
        const view = open(`/dhcp/leases?scope=${LAN_ID}`);
        await loaded();
        const bar = await screen.findByTestId("leases-utilization");
        await waitFor(() => expect(bar.dataset.value).toBe("13"));
        const facts = Object.fromEntries(within(bar).getAllByTestId("util-fact").map((el) => [el.dataset.key, el.querySelector("b")?.textContent]));
        expect(facts).toEqual({ leased: "12", reserved: "0", abandoned: "0", free: "78", pool_size: "90" });
        expect(within(bar).getByTestId("util-at").textContent).toMatch(/^Read at \d/);
        expect(within(bar).getByTestId("scope-util").querySelector('[role="img"]')?.getAttribute("aria-label")).toBe("13 percent used");
        expect(screen.queryByTestId("leases-scope-bars")).toBeNull();
        expect(await axeViolations(view.container)).toEqual([]);
      });

      it("shows the first six scopes by network, the fullest first, and links to the list for the rest", async () => {
        manyScopes();
        const spy = vi.spyOn(globalThis, "fetch");
        open();
        await loaded();
        const bars = await screen.findByTestId("leases-scope-bars");
        await waitFor(() => expect(within(bars).getAllByTestId("scope-util")).toHaveLength(6));
        // The first six by network hold 10, 80, 30, 95, 50 and 20 percent.
        await waitFor(() => expect(within(bars).getAllByTestId("leases-scope-bar").map((b) => b.dataset.key)).toEqual(["192.0.2.96/27", "192.0.2.32/27", "192.0.2.128/27", "192.0.2.64/27", "192.0.2.160/27", "192.0.2.0/27"]));
        const more = within(bars).getByTestId("leases-scope-more");
        expect(more.textContent).toBe("and 2 more scopes");
        expect(more.dataset.count).toBe("2");
        expect(more.getAttribute("href")).toBe("/dhcp");
        // Only the scopes with a bar are read.
        expect(new Set(utilReads(spy).map((url) => url.pathname)).size).toBe(6);
      });

      it("takes the scope of a bar as the filter of the list", async () => {
        const spy = vi.spyOn(globalThis, "fetch");
        open();
        await loaded();
        const bars = await screen.findAllByTestId("leases-scope-bar");
        fireEvent.click(bars.find((b) => b.dataset.key === LAN)!);
        await waitFor(() => expect(leaseReads(spy).at(-1)!.searchParams.get("scope")).toBe(LAN_ID));
        fireEvent.change(screen.getByTestId("filter-scope"), { target: { value: "" } });
        await waitFor(() => expect(screen.getByTestId("leases-live-strip").dataset.scope).toBe(""));
        expect((await screen.findAllByTestId("leases-scope-bar")).length).toBeGreaterThan(0);
      });
    });

    describe("the bars follow the refreshes of the list", () => {
      it("reads the bar of the chosen scope again with a refresh of the list, once for a burst", async () => {
        const { feed } = stream();
        const spy = vi.spyOn(globalThis, "fetch");
        open(`/dhcp/leases?scope=${LAN_ID}`);
        await loaded();
        await waitFor(() => expect((screen.getByTestId("leases-utilization") as HTMLElement).dataset.value).toBe("13"));
        const before = utilReads(spy).length;
        const listBefore = leaseReads(spy).length;
        expect(before).toBe(1);
        for (let i = 0; i < 300; i += 1) feed(i);
        await waitFor(() => expect(utilReads(spy).length).toBe(before + 1));
        await new Promise((resolve) => setTimeout(resolve, 300));
        expect(utilReads(spy).length).toBe(before + 1);
        expect(leaseReads(spy).length).toBe(listBefore + 1);
      });

      it("shows a changed figure after the refresh", async () => {
        const { feed } = stream();
        open(`/dhcp/leases?scope=${LAN_ID}`);
        await loaded();
        await waitFor(() => expect(screen.getByTestId("leases-utilization").dataset.value).toBe("13"));
        server.use(
          http.get("/api/v1/dhcp/scopes/:prefix/utilization", ({ params }) =>
            HttpResponse.json({ prefix: params.prefix, pool_size: 90, leased: 72, reserved: 0, abandoned: 0, free: 18, utilization: 0.8, at: new Date().toISOString() }),
          ),
        );
        feed(1);
        await waitFor(() => expect(screen.getByTestId("leases-utilization").dataset.value).toBe("80"));
        expect(within(screen.getByTestId("leases-utilization")).getAllByTestId("util-fact")[0]?.querySelector("b")?.textContent).toBe("72");
      });

      it("reads the bars of the scopes again, and orders them anew", async () => {
        manyScopes();
        const { feed } = stream();
        const spy = vi.spyOn(globalThis, "fetch");
        open();
        await loaded();
        const bars = await screen.findByTestId("leases-scope-bars");
        await waitFor(() => expect(within(bars).getAllByTestId("scope-util")).toHaveLength(6));
        const before = utilReads(spy).length;
        used.splice(0, 1, 99);
        feed(1);
        await waitFor(() => expect(utilReads(spy).length).toBe(before + 6));
        await waitFor(() => expect(within(bars).getAllByTestId("leases-scope-bar")[0]?.dataset.key).toBe("192.0.2.0/27"));
        used.splice(0, 1, 10);
      });

      it("does not read the bars while the view is paused", async () => {
        const { feed } = stream();
        const spy = vi.spyOn(globalThis, "fetch");
        open(`/dhcp/leases?scope=${LAN_ID}`);
        await loaded();
        await waitFor(() => expect(utilReads(spy).length).toBe(1));
        fireEvent.click(screen.getByTestId("leases-live"));
        feed(1);
        await new Promise((resolve) => setTimeout(resolve, 300));
        expect(utilReads(spy).length).toBe(1);
        fireEvent.click(screen.getByTestId("leases-live"));
        await waitFor(() => expect(utilReads(spy).length).toBe(2));
      });
    });

    describe("new since you opened the page", () => {
      it("counts the grants since the page was opened and not those before", async () => {
        const { feed } = stream();
        const spy = vi.spyOn(globalThis, "fetch");
        const before = Date.now();
        open();
        await loaded();
        await ready();
        // The seed holds twelve grants, all of them hours old.
        expect(count()).toBe("0");
        expect(text()).toBe("0 new leases since you opened this page");
        expect(screen.getByTestId("leases-new").dataset.state).toBe("live");
        const first = grantReads(spy).at(-1)!.searchParams;
        expect(first.get("limit")).toBe("1000");
        expect(first.get("scope")).toBeNull();
        expect(Date.parse(first.get("from")!)).toBeGreaterThanOrEqual(before);

        grantMockLease({ mac: docMac(0x50), hostname: "new-1" });
        feed(1);
        await waitFor(() => expect(count()).toBe("1"));
        expect(text()).toBe("1 new lease since you opened this page");
        grantMockLease({ mac: docMac(0x51), hostname: "new-2" });
        feed(2);
        await waitFor(() => expect(count()).toBe("2"));
        expect(text()).toBe("2 new leases since you opened this page");
        // A renewal is no grant.
        const template = dhcpLeaseState().events[0]!;
        dhcpLeaseState().events.push({ ...template, at: new Date().toISOString(), kind: "renewed" });
        feed(3);
        await new Promise((resolve) => setTimeout(resolve, 300));
        expect(count()).toBe("2");
      });

      it("links to the history of the same grants", async () => {
        const spy = vi.spyOn(globalThis, "fetch");
        open();
        await loaded();
        await ready();
        const from = grantReads(spy).at(-1)!.searchParams.get("from")!;
        const link = screen.getByTestId("leases-new-link");
        const url = new URL(link.getAttribute("href")!, "http://localhost");
        expect(url.pathname).toBe("/dhcp/history");
        expect(url.searchParams.get("kind")).toBe("granted");
        expect(url.searchParams.get("from")).toBe(from);
        expect(url.searchParams.get("scope")).toBeNull();
        expect(link.textContent).toBe("Show in history");
      });

      it("counts the grants of the chosen scope, keeps its start when the filters change, and links with the scope", async () => {
        const { feed } = stream();
        const spy = vi.spyOn(globalThis, "fetch");
        open();
        await loaded();
        await ready();
        const from = grantReads(spy).at(-1)!.searchParams.get("from")!;
        grantMockLease({ mac: docMac(0x52), hostname: "lan-1" });
        grantElsewhere(2);
        feed(1);
        await waitFor(() => expect(count()).toBe("3"));

        fireEvent.change(screen.getByTestId("filter-scope"), { target: { value: LAN_ID } });
        await waitFor(() => expect(grantReads(spy).at(-1)!.searchParams.get("scope")).toBe(LAN_ID));
        await waitFor(() => expect(count()).toBe("1"));
        expect(grantReads(spy).at(-1)!.searchParams.get("from")).toBe(from);
        const link = new URL(screen.getByTestId("leases-new-link").getAttribute("href")!, "http://localhost");
        expect(link.searchParams.get("scope")).toBe(LAN_ID);
        expect(link.searchParams.get("from")).toBe(from);

        fireEvent.change(screen.getByTestId("filter-addr"), { target: { value: "192.0.2.1" } });
        await waitFor(() => expect(leaseReads(spy).at(-1)!.searchParams.get("addr")).toBe("192.0.2.1"));
        await new Promise((resolve) => setTimeout(resolve, 50));
        expect(grantReads(spy).at(-1)!.searchParams.get("from")).toBe(from);
        expect(count()).toBe("1");
      });

      it("says 1,000+ when there are more grants than one page holds", async () => {
        const { feed } = stream();
        open();
        await loaded();
        await ready();
        grantElsewhere(1000);
        feed(1);
        await waitFor(() => expect(count()).toBe("1000"));
        expect(screen.getByTestId("leases-new").dataset.state).toBe("live");
        grantElsewhere(5);
        feed(2);
        await waitFor(() => expect(screen.getByTestId("leases-new").dataset.state).toBe("capped"));
        expect(text()).toBe("1,000+ new leases since you opened this page");
        expect(count()).toBe("1000");
      });

      it("counts from now on when it is reset", async () => {
        const { feed } = stream();
        const spy = vi.spyOn(globalThis, "fetch");
        open();
        await loaded();
        await ready();
        const first = grantReads(spy).at(-1)!.searchParams.get("from")!;
        grantMockLease({ mac: docMac(0x53), hostname: "before-reset" });
        feed(1);
        await waitFor(() => expect(count()).toBe("1"));
        await new Promise((resolve) => setTimeout(resolve, 15));
        fireEvent.click(screen.getByTestId("leases-new-reset"));
        await waitFor(() => expect(grantReads(spy).at(-1)!.searchParams.get("from")).not.toBe(first));
        expect(Date.parse(grantReads(spy).at(-1)!.searchParams.get("from")!)).toBeGreaterThan(Date.parse(first));
        await waitFor(() => expect(count()).toBe("0"));
        expect(new URL(screen.getByTestId("leases-new-link").getAttribute("href")!, "http://localhost").searchParams.get("from")).toBe(grantReads(spy).at(-1)!.searchParams.get("from"));
        await new Promise((resolve) => setTimeout(resolve, 15));
        grantMockLease({ mac: docMac(0x54), hostname: "after-reset" });
        feed(2);
        await waitFor(() => expect(count()).toBe("1"));
      });

      it("says it is paused while Live is off and reads nothing, then reads when Live is on again", async () => {
        const { feed } = stream();
        const spy = vi.spyOn(globalThis, "fetch");
        open();
        await loaded();
        await ready();
        fireEvent.click(screen.getByTestId("leases-live"));
        expect(screen.getByTestId("leases-new").dataset.state).toBe("paused");
        expect(text()).toBe("New leases are not counted while Live is off");
        const reads0 = grantReads(spy).length;
        grantMockLease({ mac: docMac(0x55), hostname: "while-paused" });
        feed(1);
        fireEvent.click(screen.getByTestId("leases-refresh"));
        fireEvent.click(screen.getByTestId("leases-new-reset"));
        await new Promise((resolve) => setTimeout(resolve, 300));
        expect(grantReads(spy).length).toBe(reads0);
        expect(screen.getByTestId("leases-new").dataset.state).toBe("paused");
        expect(screen.getByTestId("leases-new-link")).toBeTruthy();

        grantMockLease({ mac: docMac(0x56), hostname: "after-pause" });
        fireEvent.click(screen.getByTestId("leases-live"));
        await waitFor(() => expect(screen.getByTestId("leases-new").dataset.state).toBe("live"));
        await waitFor(() => expect(count()).toBe("1"));
        expect(grantReads(spy).length).toBeGreaterThan(reads0);
      });

      it("reads the count once for a burst of events", async () => {
        const { feed } = stream();
        const spy = vi.spyOn(globalThis, "fetch");
        open();
        await loaded();
        await ready();
        const before = grantReads(spy).length;
        for (let i = 0; i < 300; i += 1) feed(i);
        await waitFor(() => expect(grantReads(spy).length).toBe(before + 1));
        await new Promise((resolve) => setTimeout(resolve, 300));
        expect(grantReads(spy).length).toBe(before + 1);
      });

      it.each([403, 501, 409])("is hidden when the history answers %i, and the rest of the strip stays", async (status) => {
        server.use(http.get("/api/v1/dhcp/history", () => problem(status, "dhcp.history.x")));
        open(`/dhcp/leases?scope=${LAN_ID}`);
        await loaded();
        await screen.findByTestId("leases-utilization");
        await waitFor(() => expect(screen.queryByTestId("leases-new")).toBeNull());
        expect(screen.queryByTestId("leases-new-link")).toBeNull();
        expect(screen.queryByTestId("leases-new-reset")).toBeNull();
        expect(screen.getByTestId("leases-live-strip")).toBeTruthy();
      });

      it("keeps the count and the page working when a read fails for another reason", async () => {
        const { feed } = stream();
        open();
        await loaded();
        await ready();
        server.use(http.get("/api/v1/dhcp/history", () => problem(503, "dhcp.store_refused")));
        grantMockLease({ mac: docMac(0x57), hostname: "unseen" });
        feed(1);
        await waitFor(() => expect(row(GRID, "192.0.2.112")).toBeTruthy());
        await new Promise((resolve) => setTimeout(resolve, 100));
        expect(screen.getByTestId("leases-new")).toBeTruthy();
        expect(count()).toBe("0");
      });
    });

    it("speaks Swedish", async () => {
      await setLocale("sv");
      const { feed } = stream();
      open(`/dhcp/leases?scope=${LAN_ID}`);
      await loaded();
      await screen.findByTestId("leases-utilization");
      await waitFor(() => expect(screen.getByTestId("leases-new").textContent).toBe("0 nya lån sedan du öppnade sidan"));
      grantMockLease({ mac: docMac(0x58), hostname: "sv-1" });
      feed(1);
      await waitFor(() => expect(screen.getByTestId("leases-new").textContent).toBe("1 nytt lån sedan du öppnade sidan"));
      expect(screen.getByTestId("leases-new-link").textContent).toBe("Visa i historiken");
      expect(screen.getByTestId("leases-new-reset").textContent).toBe("Nollställ");
      expect(screen.getByTestId("leases-scope-link").textContent).toBe("Öppna omfånget");
      fireEvent.click(screen.getByTestId("leases-live"));
      expect(screen.getByTestId("leases-new").textContent).toBe("Nya lån räknas inte medan Live är av");
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
