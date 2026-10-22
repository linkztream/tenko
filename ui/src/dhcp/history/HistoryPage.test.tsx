// The lease history: the events newest first, the filters sent as query parameters (the address from
// a link, the MAC address, the scope, the kind, the time range as RFC 3339), paging with the cursor,
// the link back to the leases, the live view, the states without a service, Swedish.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { events, type ApiEvent } from "../../api/events";
import { db } from "../../api/mock/db";
import { dhcpLeaseState, docMac, grantMockLease } from "../../api/mock/routes-dhcp-leases";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { cell, dhcpNotBuilt, dhcpSwitchedOff, rows } from "../testkit";
import HistoryPage from "./HistoryPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  vi.restoreAllMocks();
  setSessionForTest(null);
  await setLocale("en");
});

const GRID = "dhcp-history";
const open = (url = "/dhcp/history") => renderRoute(HistoryPage, { url, path: "/dhcp/history" });
const loaded = () => waitFor(() => expect(rows(GRID).length).toBeGreaterThan(0));

function historyReads(spy: { mock: { calls: unknown[][] } }): URL[] {
  return spy.mock.calls.map(([url]) => new URL(String(url), "http://localhost")).filter((url) => url.pathname === "/api/v1/dhcp/history");
}

describe("the lease history", () => {
  it("lists the events newest first with kind, address, client, state after, end, name and node", async () => {
    const view = open();
    await loaded();
    const first = rows(GRID)[0]!;
    // The four renewals are the newest events; of equal time the later one comes first.
    expect(first.dataset.key).toBe("192.0.2.103 renewed");
    expect(within(first).getByTestId("event-kind").textContent).toBe("Renewed");
    expect(cell(first, "mac").textContent).toBe("00:00:5e:00:53:13");
    expect(within(first).getByTestId("event-state").dataset.key).toBe("active");
    expect(cell(first, "name").textContent).toBe("host-4");
    expect(cell(first, "node").textContent).toBe("1");
    const kinds = rows(GRID).map((r) => within(r).getByTestId("event-kind").dataset.key);
    expect(kinds.slice(0, 4)).toEqual(["renewed", "renewed", "renewed", "renewed"]);
    expect(kinds).toContain("granted");
    expect(kinds).toContain("declined");
    expect(kinds).toContain("expired");
    expect(kinds).toContain("released");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("links an address to its leases", async () => {
    open();
    await loaded();
    expect(within(rows(GRID)[0]!).getByTestId("event-lease-link").getAttribute("href")).toBe("/dhcp/leases?addr=192.0.2.103");
  });

  it("shows the history of the address a link names", async () => {
    open("/dhcp/history?addr=192.0.2.100");
    await waitFor(() => expect(rows(GRID).map((r) => r.dataset.key).sort()).toEqual(["192.0.2.100 granted", "192.0.2.100 renewed"]));
    expect((screen.getByTestId("filter-addr") as HTMLInputElement).value).toBe("192.0.2.100");
  });

  it("sends the filters as query parameters", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    open();
    await loaded();
    const last = () => historyReads(spy).at(-1)!.searchParams;

    fireEvent.change(screen.getByTestId("filter-addr"), { target: { value: "192.0.2.101" } });
    await waitFor(() => expect(last().get("addr")).toBe("192.0.2.101"));
    await waitFor(() => expect(rows(GRID).map((r) => r.dataset.key).sort()).toEqual(["192.0.2.101 granted", "192.0.2.101 renewed"]));

    fireEvent.change(screen.getByTestId("filter-kind"), { target: { value: "renewed" } });
    await waitFor(() => expect(last().get("kind")).toBe("renewed"));
    await waitFor(() => expect(rows(GRID).map((r) => r.dataset.key)).toEqual(["192.0.2.101 renewed"]));

    fireEvent.change(screen.getByTestId("filter-kind"), { target: { value: "" } });
    fireEvent.change(screen.getByTestId("filter-addr"), { target: { value: "" } });
    fireEvent.change(screen.getByTestId("filter-mac"), { target: { value: "00:00:5E:00:53:1A" } });
    await waitFor(() => expect(last().get("mac")).toBe("00:00:5e:00:53:1a"));
    await waitFor(() => expect(rows(GRID).map((r) => r.dataset.key).sort()).toEqual(["192.0.2.110 granted", "192.0.2.110 released"]));

    fireEvent.change(screen.getByTestId("filter-mac"), { target: { value: "" } });
    const scope = dhcpLeaseState().leases[0]!.scope;
    fireEvent.change(screen.getByTestId("filter-scope"), { target: { value: scope } });
    await waitFor(() => expect(last().get("scope")).toBe(scope));

    // The fields show local time; the query carries RFC 3339.
    const from = "2020-01-01T10:00";
    const to = "2020-01-01T11:30";
    fireEvent.change(screen.getByTestId("filter-from"), { target: { value: from } });
    fireEvent.change(screen.getByTestId("filter-to"), { target: { value: to } });
    const iso = (local: string) => new Date(local).toISOString().replace(/\.\d{3}Z$/, "Z");
    await waitFor(() => expect(last().get("from")).toBe(iso(from)));
    await waitFor(() => expect(last().get("to")).toBe(iso(to)));
    // That range is long before the seed: no event.
    expect(await screen.findByTestId("dhcp-history-empty")).toBeTruthy();
    expect(screen.getByTestId("dhcp-history-empty").dataset.filtered).toBe("true");

    fireEvent.click(screen.getByTestId("history-reset"));
    await waitFor(() => expect(last().get("from")).toBeNull());
    expect(last().get("to")).toBeNull();
    expect(last().get("scope")).toBeNull();
    await loaded();
  });

  it("reads the next page with the cursor", async () => {
    for (let i = 0; i < 90; i += 1) grantMockLease({ mac: docMac(0x40 + i), hostname: `bulk-${i}` });
    const spy = vi.spyOn(globalThis, "fetch");
    open();
    await loaded();
    const more = await screen.findByTestId("history-more");
    expect(historyReads(spy).at(-1)!.searchParams.get("cursor")).toBeNull();
    fireEvent.click(more);
    await waitFor(() => expect(historyReads(spy).some((url) => url.searchParams.get("cursor") !== null)).toBe(true));
    await waitFor(() => expect(screen.queryByTestId("history-more")).toBeNull());
  });

  describe("the live view", () => {
    function feed(subscribe: { mock: { calls: unknown[][] } }, n: number, tables = ["dhcp.history"]): void {
      const handler = subscribe.mock.calls.find(([topic]) => topic === "dhcp")?.[1] as ((event: ApiEvent) => void) | undefined;
      if (!handler) throw new Error("the page did not subscribe to the dhcp topic");
      const revision = db.revision + 100_000 + n;
      handler({ topic: "dhcp", type: "dhcp", objects: [], deleted: [], revision, data: { tables, revision } });
    }

    it("shows a new event without a reload and pauses with the toggle", async () => {
      const subscribe = vi.spyOn(events, "subscribe");
      open();
      await loaded();
      grantMockLease({ mac: docMac(0x50), hostname: "client-live" });
      feed(subscribe, 1);
      await waitFor(() => expect(rows(GRID)[0]!.dataset.key).toBe("192.0.2.112 granted"));

      const toggle = screen.getByTestId("history-live") as HTMLInputElement;
      fireEvent.click(toggle);
      grantMockLease({ mac: docMac(0x51), hostname: "client-paused" });
      feed(subscribe, 2);
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(rows(GRID)[0]!.dataset.key).toBe("192.0.2.112 granted");
      fireEvent.click(toggle);
      await waitFor(() => expect(rows(GRID)[0]!.dataset.key).toBe("192.0.2.113 granted"));
    });

    it("ignores the events of the lease table", async () => {
      const subscribe = vi.spyOn(events, "subscribe");
      const spy = vi.spyOn(globalThis, "fetch");
      open();
      await loaded();
      const before = historyReads(spy).length;
      feed(subscribe, 1, ["dhcp.leases"]);
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(historyReads(spy).length).toBe(before);
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
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("Lånehistorik");
    expect(within(rows(GRID)[0]!).getByTestId("event-kind").textContent).toBe("Förnyat");
    expect(screen.getByLabelText("Händelse")).toBeTruthy();
  });
});
